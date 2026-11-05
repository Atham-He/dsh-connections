/**
 * Host half of `@local/dsh-connections`: SSH connections for the DeepSeek
 * Harness, modelled on the SSH-host mode of Codex's remote connections.
 *
 * - Tools let the agent run one-shot commands, keep an interactive SSH
 *   connection, copy files, open local port forwards, and start a remote
 *   DeepSeek Harness Web UI through SSH and forward it to localhost.
 * - Two authenticated web routes back the Connections settings page.
 *
 * Every child process is owned by one ConnectionManager instance created on
 * first use; the plugin effect disposes it and terminates anything still live.
 */
import { homedir, hostname } from 'node:os'
import { join } from 'node:path'
import { loadSshConfig, describeHost, parseDestination } from './lib/ssh-config.js'
import { ConnectionManager } from './lib/connections.js'
import { ControlService } from './lib/control/service.js'

export const inject = ['tools', 'webServer', 'connection', 'deepseekAccount']

const MAX_INPUT_BYTES = 64 * 1024
const DEFAULT_EXEC_TIMEOUT_MS = 120_000
const MAX_EXEC_TIMEOUT_MS = 30 * 60_000
const DEFAULT_MAX_OUTPUT_BYTES = 128 * 1024
const MAX_MAX_OUTPUT_BYTES = 1024 * 1024

const HOST_PATTERN = /^[^\s\x00-\x1f-][^\s\x00-\x1f]*$/
const SESSION_PATTERN = /^[A-Za-z0-9._-]{1,128}$/
const TUNNEL_PATTERN = /^[A-Za-z0-9._-]{1,128}$/
const PROFILE_PATTERN = /^[A-Za-z0-9._-]{1,64}$/

const HOST_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    alias: { type: 'string' },
    hostName: { type: 'string' },
    user: { type: 'string' },
    port: { type: 'integer' },
    identityFile: { type: 'string' },
    proxyJump: { type: 'string' },
    source: { type: 'string' },
  },
  required: ['alias', 'source'],
}

const TUNNEL_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    tunnelId: { type: 'string' },
    host: { type: 'string' },
    localPort: { type: 'integer' },
    remoteHost: { type: 'string' },
    remotePort: { type: 'integer' },
    pid: { type: 'integer' },
    localUrl: { type: 'string' },
  },
  required: ['tunnelId', 'host', 'localPort', 'remoteHost', 'remotePort'],
}

const NULLABLE_INTEGER = { oneOf: [{ type: 'integer' }, { type: 'null' }] }
const NULLABLE_STRING = { oneOf: [{ type: 'string' }, { type: 'null' }] }

const textResult = (text) => [{ type: 'text', text }]
const jsonResult = (value) => textResult(JSON.stringify(value, null, 2))

function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function asText(value) {
  return typeof value === 'string' ? value : safeJson(value)
}

function trimOutput(text, max) {
  const encoded = typeof text === 'string' ? text : ''
  if (Buffer.byteLength(encoded, 'utf8') <= max) return { text: encoded, truncated: false }
  const buffer = Buffer.from(encoded, 'utf8')
  const cut = buffer.subarray(buffer.length - max).toString('utf8')
  return { text: cut, truncated: true }
}

function requireObject(args) {
  if (typeof args !== 'object' || args === null || Array.isArray(args)) {
    throw new Error('arguments must be an object')
  }
  return args
}

function stringArg(args, key, { required = true, min = 1, max = MAX_INPUT_BYTES, pattern, patternHint } = {}) {
  const value = args[key]
  if (value === undefined || value === null) {
    if (!required) return undefined
    throw new Error(`"${key}" is required`)
  }
  if (typeof value !== 'string') throw new Error(`"${key}" must be a string`)
  if (value.length < min) throw new Error(`"${key}" must not be empty`)
  if (Buffer.byteLength(value, 'utf8') > max) throw new Error(`"${key}" is too large`)
  if (pattern && !pattern.test(value)) throw new Error(`"${key}" is invalid${patternHint ? `: ${patternHint}` : ''}`)
  return value
}

function integerArg(args, key, { required = false, fallback, min, max } = {}) {
  const value = args[key]
  if (value === undefined || value === null) {
    if (required) throw new Error(`"${key}" is required`)
    return fallback
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new Error(`"${key}" must be an integer`)
  }
  if (min !== undefined && value < min) throw new Error(`"${key}" must be at least ${min}`)
  if (max !== undefined && value > max) throw new Error(`"${key}" must be at most ${max}`)
  return value
}

function booleanArg(args, key, fallback) {
  const value = args[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') throw new Error(`"${key}" must be a boolean`)
  return value
}

function enumArg(args, key, values, fallback) {
  const value = args[key]
  if (value === undefined || value === null) {
    if (fallback !== undefined) return fallback
    throw new Error(`"${key}" is required`)
  }
  if (!values.includes(value)) throw new Error(`"${key}" must be one of: ${values.join(', ')}`)
  return value
}

function destinationArg(args, key = 'host') {
  const value = stringArg(args, key, {
    max: 512,
    pattern: HOST_PATTERN,
    patternHint: 'pass an ~/.ssh/config alias or user@host[:port], not an option',
  })
  parseDestination(value)
  return value
}

/** Compact model-facing summary of one device-control status snapshot. */
function summarizeControlStatus(status) {
  if (typeof status !== 'object' || status === null) return ''
  const account = status.account ?? {}
  const host = status.host ?? {}
  const peers = Array.isArray(status.peers) ? status.peers : []
  const paired = Array.isArray(host.paired) ? host.paired : []
  const pending = Array.isArray(host.pending) ? host.pending : []
  const lines = []
  lines.push(
    `account: ${account.signedIn ? account.name || account.contact || account.id || 'signed in' : 'not signed in'}`,
  )
  lines.push(
    `control this computer: ${
      host.enabled
        ? `enabled (port ${host.port}, ${paired.length} paired, ${pending.length} pending)`
        : 'disabled'
    }`,
  )
  lines.push(
    `paired remote hosts: ${peers.length}${
      peers.length === 0 ? '' : ` (${peers.map((peer) => peer.name || peer.deviceId).join(', ')})`
    }`,
  )
  if (Array.isArray(status.notes)) {
    for (const note of status.notes) lines.push(`note: ${note}`)
  }
  return lines.join('\n')
}

/** Response helper shared by the settings routes. */
function sendJson(res, status, value) {
  const body = JSON.stringify(value)
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.end(body)
}

/** Read a bounded JSON request body; resolves undefined when missing/invalid. */
async function readJsonBody(req, maxBytes) {
  const chunks = []
  let total = 0
  for await (const chunk of req) {
    total += chunk.length
    if (total > maxBytes) return undefined
    chunks.push(chunk)
  }
  if (total === 0) return undefined
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    return undefined
  }
}

/**
 * Create the plugin instance.
 * @param {any} ctx - Cordis plugin context.
 */
export function apply(ctx) {
  /** @type {ConnectionManager | undefined} */
  let manager
  let disposed = false

  const webServer = ctx.get('webServer')
  const connection = ctx.get('connection')
  const account = ctx.get('deepseekAccount')

  /** @type {ControlService | undefined} */
  let controlService
  /** @type {Promise<void> | undefined} */
  let controlInit
  /** @type {Error | undefined} */
  let controlError

  if (webServer !== undefined && connection !== undefined) {
    controlService = new ControlService({
      home: process.env.DSH_CONNECTIONS_HOME ?? process.env.DSH_HOME ?? join(homedir(), '.dsh'),
      hostName: process.env.DSH_CONNECTIONS_DEVICE_NAME ?? hostname(),
      version: '0.2.1-rc.5',
      locale: 'en',
      webServer,
      connection,
      account,
      log: process.env.DSH_CONNECTIONS_DEBUG === '1' ? (message) => console.error('[dsh-connections]', message) : () => {},
    })
    controlInit = controlService.init().catch((error) => {
      controlError = error instanceof Error ? error : new Error(String(error))
    })
  }

  const controlOf = async () => {
    if (controlService === undefined) {
      throw new Error('Device control requires the Harness web runtime (webServer and connection services)')
    }
    if (controlInit !== undefined) await controlInit
    if (controlError !== undefined) throw controlError
    return controlService
  }

  const managerOf = () => {
    if (manager !== undefined) return manager
    const subprocess = ctx.get('subprocess')
    if (subprocess === undefined) {
      throw new Error('SSH connections require the Harness subprocess service, which is not mounted in this profile')
    }
    manager = new ConnectionManager({ subprocess, home: homedir() })
    return manager
  }

  const ready = async () => {
    if (disposed) throw new Error('SSH connections were unloaded')
    const instance = managerOf()
    await instance.init()
    return instance
  }

  ctx.effect(() => () => {
    disposed = true
    const instance = manager
    manager = undefined
    if (instance !== undefined) void instance.dispose().catch(() => {})
    if (controlService !== undefined) void controlService.dispose().catch(() => {})
    controlService = undefined
  })

  // ---------------------------------------------------------------------
  // Model-facing tools
  // ---------------------------------------------------------------------

  ctx.tools.register({
    name: 'ssh_hosts',
    description:
      'List SSH hosts discovered from ~/.ssh/config. Each alias can be passed to the other ssh_* tools; direct user@host[:port] targets also work.',
    parameters: { type: 'object', additionalProperties: false, properties: {}, required: [] },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          path: { type: 'string' },
          exists: { type: 'boolean' },
          hosts: { type: 'array', items: HOST_SCHEMA },
          warnings: { type: 'array', items: { type: 'string' } },
        },
        required: ['path', 'exists', 'hosts', 'warnings'],
      },
      render: (_args, value) => {
        const lines = []
        if (!value.exists) {
          lines.push(`No SSH config at ${value.path}.`)
          lines.push('Direct targets still work: user@host[:port].')
        } else if (value.hosts.length === 0) {
          lines.push(`SSH config at ${value.path} declares no concrete Host aliases.`)
        } else {
          lines.push(`SSH hosts from ${value.path}:`)
          for (const host of value.hosts) {
            const target = describeHost(host)
            const identity = host.identityFile ? `  key=${host.identityFile}` : ''
            lines.push(`  ${host.alias}  ->  ${target}${identity}`)
          }
          lines.push('Direct targets also work: user@host[:port].')
        }
        if (value.warnings.length > 0) {
          lines.push('', ...value.warnings.map((warning) => `warning: ${warning}`))
        }
        return textResult(lines.join('\n'))
      },
    },
    async execute() {
      const instance = managerOf()
      return instance.listHosts()
    },
  })

  ctx.tools.register({
    name: 'ssh_exec',
    description:
      'Run one command over SSH without a PTY and return its stdout, stderr and exit code. Use for bounded remote commands; for an interactive shell use ssh_open.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        host: { type: 'string', description: '~/.ssh/config alias or user@host[:port]' },
        command: { type: 'string', description: 'Shell command line executed on the remote host' },
        timeoutSeconds: { type: 'integer', description: 'Command timeout in seconds (default 120, max 1800)' },
        maxOutputBytes: { type: 'integer', description: 'Per-stream output cap in bytes (default 131072, max 1048576)' },
      },
      required: ['host', 'command'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string' },
          command: { type: 'string' },
          exitCode: NULLABLE_INTEGER,
          signal: NULLABLE_STRING,
          stdout: { type: 'string' },
          stderr: { type: 'string' },
          truncated: { type: 'boolean' },
          timedOut: { type: 'boolean' },
          durationMs: { type: 'integer' },
        },
        required: [
          'host',
          'command',
          'exitCode',
          'signal',
          'stdout',
          'stderr',
          'truncated',
          'timedOut',
          'durationMs',
        ],
      },
      render: (_args, value) => {
        const lines = [`$ ${value.command}`, `[host: ${value.host}]`]
        if (value.stdout.length > 0) lines.push(value.stdout.replace(/\n$/, ''))
        if (value.stderr.length > 0) lines.push('[stderr]', value.stderr.replace(/\n$/, ''))
        const flags = [`exit=${value.exitCode === null ? String(value.signal ?? 'unknown') : value.exitCode}`]
        flags.push(`duration=${value.durationMs}ms`)
        if (value.timedOut) flags.push('timedOut=true')
        if (value.truncated) flags.push('truncated=true')
        lines.push(`[${flags.join(' ')}]`)
        return textResult(lines.join('\n'))
      },
    },
    async execute(rawArgs, exec) {
      const args = requireObject(rawArgs)
      const host = destinationArg(args)
      const command = stringArg(args, 'command')
      const timeoutSeconds = integerArg(args, 'timeoutSeconds', { fallback: 120, min: 1, max: 1800 })
      const maxOutputBytes = integerArg(args, 'maxOutputBytes', {
        fallback: DEFAULT_MAX_OUTPUT_BYTES,
        min: 1024,
        max: MAX_MAX_OUTPUT_BYTES,
      })
      const instance = await ready()
      return instance.exec({
        host,
        command,
        timeoutMs: Math.min(timeoutSeconds * 1000, MAX_EXEC_TIMEOUT_MS),
        maxOutputBytes,
        signal: exec.signal,
      })
    },
  })

  ctx.tools.register({
    name: 'ssh_open',
    description:
      'Open a persistent interactive SSH connection (PTY) and return a session id. Use ssh_send to type, ssh_read to collect output, ssh_close to end it.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        host: { type: 'string', description: '~/.ssh/config alias or user@host[:port]' },
        name: { type: 'string', description: 'Optional owner-local label for the session' },
      },
      required: ['host'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          sessionId: { type: 'string' },
          host: { type: 'string' },
          pid: { type: 'integer' },
          status: { type: 'string' },
          initialOutput: { type: 'string' },
          hint: { type: 'string' },
        },
        required: ['sessionId', 'host', 'pid', 'status', 'initialOutput', 'hint'],
      },
      render: (_args, value) => {
        const lines = [`opened session ${value.sessionId} on ${value.host} (pid ${value.pid})`]
        if (value.initialOutput.length > 0) lines.push('--- output ---', value.initialOutput.replace(/\n$/, ''))
        lines.push(value.hint)
        return textResult(lines.join('\n'))
      },
    },
    async execute(rawArgs, exec) {
      const args = requireObject(rawArgs)
      const host = destinationArg(args)
      const name = stringArg(args, 'name', { required: false, min: 0, max: 128 })
      const instance = await ready()
      const session = await instance.open({ host, name })
      return {
        ...session,
        hint: `Use ssh_send({ sessionId: "${session.sessionId}", text: "..." }) to type, ssh_read to collect output, and ssh_close to disconnect.`,
      }
    },
  })

  ctx.tools.register({
    name: 'ssh_send',
    description:
      'Type text into an open SSH session, optionally press Enter, wait briefly, and return the new output. A timeout or silence does not prove the remote command finished.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        sessionId: { type: 'string' },
        text: { type: 'string' },
        submit: { type: 'boolean', description: 'Append Enter (default true)' },
        waitMs: { type: 'integer', description: 'Milliseconds to wait for output (default 1500, max 30000)' },
      },
      required: ['sessionId', 'text'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          sessionId: { type: 'string' },
          output: { type: 'string' },
          truncated: { type: 'boolean' },
          status: { type: 'string' },
          exitCode: NULLABLE_INTEGER,
        },
        required: ['sessionId', 'output', 'truncated', 'status', 'exitCode'],
      },
      render: (_args, value) => {
        const output = value.output.length > 0 ? value.output.replace(/\n$/, '') : '(no new output)'
        return textResult(`${output}\n[status: ${value.status}${value.exitCode === null ? '' : ` exit=${value.exitCode}`}]`)
      },
    },
    async execute(rawArgs, exec) {
      const args = requireObject(rawArgs)
      const sessionId = stringArg(args, 'sessionId', { max: 128, pattern: SESSION_PATTERN })
      const text = stringArg(args, 'text', { min: 0, max: MAX_INPUT_BYTES })
      const submit = booleanArg(args, 'submit', true)
      const waitMs = integerArg(args, 'waitMs', { fallback: 1500, min: 0, max: 30_000 })
      const instance = await ready()
      return instance.send({ sessionId, text, submit, waitMs, signal: exec.signal })
    },
  })

  ctx.tools.register({
    name: 'ssh_read',
    description: 'Return buffered output from an open SSH session that has not yet been returned to the caller.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: { sessionId: { type: 'string' } },
      required: ['sessionId'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          sessionId: { type: 'string' },
          output: { type: 'string' },
          truncated: { type: 'boolean' },
          status: { type: 'string' },
          exitCode: NULLABLE_INTEGER,
        },
        required: ['sessionId', 'output', 'truncated', 'status', 'exitCode'],
      },
      render: (_args, value) => {
        const output = value.output.length > 0 ? value.output.replace(/\n$/, '') : '(no buffered output)'
        return textResult(`${output}\n[status: ${value.status}${value.exitCode === null ? '' : ` exit=${value.exitCode}`}]`)
      },
    },
    async execute(rawArgs) {
      const args = requireObject(rawArgs)
      const sessionId = stringArg(args, 'sessionId', { max: 128, pattern: SESSION_PATTERN })
      const instance = await ready()
      return instance.read({ sessionId })
    },
  })

  ctx.tools.register({
    name: 'ssh_close',
    description: 'Close an open SSH session and wait for its process to end.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: { sessionId: { type: 'string' } },
      required: ['sessionId'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          sessionId: { type: 'string' },
          closed: { type: 'boolean' },
          exitCode: NULLABLE_INTEGER,
        },
        required: ['sessionId', 'closed', 'exitCode'],
      },
      render: (_args, value) =>
        textResult(`closed session ${value.sessionId}${value.exitCode === null ? '' : ` exit=${value.exitCode}`}`),
    },
    async execute(rawArgs) {
      const args = requireObject(rawArgs)
      const sessionId = stringArg(args, 'sessionId', { max: 128, pattern: SESSION_PATTERN })
      const instance = await ready()
      return instance.close({ sessionId })
    },
  })

  ctx.tools.register({
    name: 'ssh_sessions',
    description: 'List the interactive SSH sessions opened by this plugin.',
    parameters: { type: 'object', additionalProperties: false, properties: {}, required: [] },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          sessions: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                sessionId: { type: 'string' },
                host: { type: 'string' },
                name: { type: 'string' },
                pid: { type: 'integer' },
                status: { type: 'string' },
                exitCode: NULLABLE_INTEGER,
              },
              required: ['sessionId', 'host', 'pid', 'status', 'exitCode'],
            },
          },
        },
        required: ['sessions'],
      },
      render: (_args, value) => {
        if (value.sessions.length === 0) return textResult('(no SSH sessions)')
        return textResult(
          value.sessions
            .map((session) => {
              const label = session.name ? ` (${session.name})` : ''
              return `${session.sessionId}${label} ${session.host} pid=${session.pid} ${session.status}`
            })
            .join('\n'),
        )
      },
    },
    async execute() {
      const instance = await ready()
      return { sessions: instance.sessions() }
    },
  })

  ctx.tools.register({
    name: 'ssh_copy',
    description: 'Upload or download a file or directory over SSH using scp.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        host: { type: 'string', description: '~/.ssh/config alias or user@host[:port]' },
        direction: { type: 'string', enum: ['upload', 'download'] },
        localPath: { type: 'string', description: 'Absolute local path' },
        remotePath: { type: 'string', description: 'Remote path (relative paths resolve from the remote home)' },
        recursive: { type: 'boolean', description: 'Copy directories recursively' },
        timeoutSeconds: { type: 'integer', description: 'Transfer timeout in seconds (default 300)' },
      },
      required: ['host', 'direction', 'localPath', 'remotePath'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean' },
          direction: { type: 'string' },
          exitCode: NULLABLE_INTEGER,
          stderr: { type: 'string' },
          durationMs: { type: 'integer' },
        },
        required: ['ok', 'direction', 'exitCode', 'stderr', 'durationMs'],
      },
      render: (_args, value) => {
        const status = value.ok ? 'ok' : 'failed'
        const lines = [`scp ${value.direction}: ${status} (exit=${value.exitCode ?? 'null'}, ${value.durationMs}ms)`]
        if (value.stderr.length > 0) lines.push(value.stderr.replace(/\n$/, ''))
        return textResult(lines.join('\n'))
      },
    },
    async execute(rawArgs, exec) {
      const args = requireObject(rawArgs)
      const host = destinationArg(args)
      const direction = enumArg(args, 'direction', ['upload', 'download'])
      const localPath = stringArg(args, 'localPath', { max: 1024 })
      if (localPath.startsWith('-')) throw new Error('"localPath" must not start with "-"')
      const remotePath = stringArg(args, 'remotePath', { max: 1024 })
      if (remotePath.startsWith('-')) throw new Error('"remotePath" must not start with "-"')
      const recursive = booleanArg(args, 'recursive', false)
      const timeoutSeconds = integerArg(args, 'timeoutSeconds', { fallback: 300, min: 1, max: 1800 })
      const instance = await ready()
      return instance.copy({
        host,
        direction,
        localPath,
        remotePath,
        recursive,
        timeoutMs: Math.min(timeoutSeconds * 1000, MAX_EXEC_TIMEOUT_MS),
        signal: exec.signal,
      })
    },
  })

  ctx.tools.register({
    name: 'ssh_tunnel',
    description:
      'Manage local SSH port forwards. action=open forwards a local port to a remote host:port; action=list shows open tunnels; action=close stops one.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['open', 'list', 'close'], description: 'Defaults to open' },
        host: { type: 'string', description: '~/.ssh/config alias or user@host[:port] (open)' },
        remoteHost: { type: 'string', description: 'Remote target host, default 127.0.0.1' },
        remotePort: { type: 'integer', description: 'Remote target port (open)' },
        localPort: { type: 'integer', description: 'Local listen port, 0 for an OS-assigned port' },
        tunnelId: { type: 'string', description: 'Tunnel id (close)' },
      },
      required: [],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string' },
          tunnel: TUNNEL_SCHEMA,
          tunnels: { type: 'array', items: TUNNEL_SCHEMA },
          closed: { type: 'boolean' },
          message: { type: 'string' },
        },
        required: ['action', 'message'],
      },
      render: (_args, value) => {
        if (value.action === 'list') {
          if (value.tunnels.length === 0) return textResult('(no SSH tunnels)')
          return textResult(
            value.tunnels
              .map(
                (tunnel) =>
                  `${tunnel.tunnelId} 127.0.0.1:${tunnel.localPort} -> ${tunnel.host}:${tunnel.remoteHost}:${tunnel.remotePort} pid=${tunnel.pid}`,
              )
              .join('\n'),
          )
        }
        if (value.action === 'open' && value.tunnel !== undefined) {
          return textResult(
            `tunnel ${value.tunnel.tunnelId} open: ${value.tunnel.localUrl ?? `http://127.0.0.1:${value.tunnel.localPort}/`} -> ${value.tunnel.host}:${value.tunnel.remoteHost}:${value.tunnel.remotePort}\n${value.message}`,
          )
        }
        return textResult(`${value.action}: ${value.message}`)
      },
    },
    async execute(rawArgs, exec) {
      const args = requireObject(rawArgs)
      const action = enumArg(args, 'action', ['open', 'list', 'close'], 'open')
      const instance = await ready()
      if (action === 'list') {
        return { action, tunnels: instance.tunnelList(), message: 'Open SSH tunnels listed.' }
      }
      if (action === 'close') {
        const tunnelId = stringArg(args, 'tunnelId', { max: 128, pattern: TUNNEL_PATTERN })
        const result = await instance.tunnelClose({ tunnelId })
        return { action, closed: result.closed, message: `Closed tunnel ${tunnelId}.` }
      }
      const host = destinationArg(args)
      const remoteHost = stringArg(args, 'remoteHost', { required: false, max: 255 }) ?? '127.0.0.1'
      const remotePort = integerArg(args, 'remotePort', { required: true, min: 1, max: 65_535 })
      const localPort = integerArg(args, 'localPort', { fallback: 0, min: 0, max: 65_535 })
      const tunnel = await instance.tunnelOpen({ host, remoteHost, remotePort, localPort })
      return {
        action,
        tunnel,
        message: `Local port ${tunnel.localPort} now forwards to ${tunnel.host}:${tunnel.remoteHost}:${tunnel.remotePort}.`,
      }
    },
  })

  ctx.tools.register({
    name: 'ssh_harness',
    description:
      'Connect this machine to a DeepSeek Harness running on another machine over SSH. action=status checks the remote dsh install; action=start starts `dsh web` there and forwards it to localhost, returning a URL to open; action=stop stops it.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        host: { type: 'string', description: '~/.ssh/config alias or user@host[:port] of the remote machine' },
        action: { type: 'string', enum: ['status', 'start', 'stop'], description: 'Defaults to status' },
        profile: { type: 'string', description: 'Remote dsh profile name (default "web")' },
        remotePort: { type: 'integer', description: 'Remote listen port (default 39001)' },
        localPort: { type: 'integer', description: 'Local forward port (defaults to remotePort so same-port OAuth callbacks work)' },
        readyTimeoutSeconds: { type: 'integer', description: 'Startup wait in seconds (default 60)' },
      },
      required: ['host'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string' },
          host: { type: 'string' },
          installed: { type: 'boolean' },
          version: { type: 'string' },
          running: { type: 'boolean' },
          remotePort: { type: 'integer' },
          localPort: { type: 'integer' },
          url: { type: 'string' },
          pid: { type: 'integer' },
          logPath: { type: 'string' },
          message: { type: 'string' },
        },
        required: ['action', 'host', 'installed', 'running', 'message'],
      },
      render: (_args, value) => {
        const lines = [`remote harness ${value.action} on ${value.host}: ${value.message}`]
        if (value.installed === false) {
          lines.push('remote dsh is not installed or not on the non-interactive PATH')
        }
        if (value.version) lines.push(`dsh: ${value.version}`)
        if (value.url) lines.push(`open: ${value.url}`)
        if (value.running && value.pid !== undefined) lines.push(`remote pid: ${value.pid}`)
        if (value.logPath) lines.push(`remote log: ${value.logPath}`)
        return textResult(lines.join('\n'))
      },
    },
    async execute(rawArgs, exec) {
      const args = requireObject(rawArgs)
      const host = destinationArg(args)
      const action = enumArg(args, 'action', ['status', 'start', 'stop'], 'status')
      const profile = stringArg(args, 'profile', { required: false, max: 64, pattern: PROFILE_PATTERN }) ?? 'web'
      const remotePort = integerArg(args, 'remotePort', { fallback: 39_001, min: 1, max: 65_535 })
      const localPort = integerArg(args, 'localPort', { fallback: 0, min: 0, max: 65_535 })
      const readyTimeoutSeconds = integerArg(args, 'readyTimeoutSeconds', { fallback: 60, min: 5, max: 300 })
      const instance = await ready()
      return instance.harness({
        host,
        action,
        profile,
        remotePort,
        localPort: localPort === 0 ? undefined : localPort,
        readyTimeoutMs: readyTimeoutSeconds * 1000,
        signal: exec.signal,
      })
    },
  })

  ctx.tools.register({
    name: 'remote_control',
    description:
      'Connect this DeepSeek Harness to another one signed into the same DeepSeek account. action=status shows account, this device and paired devices; action=enable/disable allows or stops other devices controlling this computer; action=pairing_link creates a one-time secret link for another device; action=pair consumes such a link; action=connect opens the paired host GUI through an encrypted tunnel and returns a localhost URL; action=disconnect stops the tunnel; action=unpair removes a pairing.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: ['status', 'enable', 'disable', 'pairing_link', 'pair', 'connect', 'disconnect', 'unpair'],
          description: 'Operation to perform',
        },
        port: { type: 'integer', description: 'Listen port for "enable" (default 39002)' },
        link: { type: 'string', description: 'Pairing link for "pair"' },
        deviceId: { type: 'string', description: 'Device id for "connect", "disconnect" or "unpair"' },
        side: { type: 'string', enum: ['guest', 'peer'], description: '"guest" for a device paired to this computer, "peer" for a remote host this computer controls' },
      },
      required: ['action'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string' },
          message: { type: 'string' },
          status: { type: 'object' },
          link: { type: 'string' },
          guestDeviceId: { type: 'string' },
          expiresAt: { type: 'integer' },
          peer: { type: 'object' },
          deviceId: { type: 'string' },
          url: { type: 'string' },
          localPort: { type: 'integer' },
          webPort: { type: 'integer' },
        },
        required: ['action', 'message'],
      },
      render: (_args, value) => {
        const lines = [`device control: ${value.action} — ${value.message}`]
        if (value.link !== undefined) {
          lines.push('pairing link (secret, single use):', value.link)
        }
        if (value.url !== undefined) {
          lines.push(`open: ${value.url}`)
        }
        if (value.status !== undefined) {
          const summary = summarizeControlStatus(value.status)
          if (summary !== '') lines.push('', summary)
        }
        return textResult(lines.join('\n'))
      },
    },
    async execute(rawArgs) {
      const args = requireObject(rawArgs)
      const action = enumArg(args, 'action', [
        'status',
        'enable',
        'disable',
        'pairing_link',
        'pair',
        'connect',
        'disconnect',
        'unpair',
      ])
      const instance = await controlOf()
      if (action === 'status') {
        const status = await instance.status()
        return { action, message: 'Device control status.', status }
      }
      if (action === 'enable' || action === 'disable') {
        if (action === 'disable') {
          const status = await instance.disable()
          return { action, message: 'Other devices can no longer control this computer.', status }
        }
        const port = integerArg(args, 'port', { fallback: undefined, min: 1024, max: 65535 })
        const status = await instance.enable(port === undefined ? {} : { port })
        return {
          action,
          message: status?.host?.enabled
            ? `Other devices on the same account may now connect on port ${status.host.port}.`
            : 'Remote control was not enabled; see the status notes.',
          status,
        }
      }
      if (action === 'pairing_link') {
        const result = await instance.createPairingLink()
        const status = await instance.status()
        return {
          action,
          message: 'Pairing link created. Treat it as a secret; paste it into the other device\'s Connections page.',
          link: result.link,
          ...(typeof result.guestDeviceId === 'string' ? { guestDeviceId: result.guestDeviceId } : {}),
          ...(Number.isSafeInteger(result.expiresAt) ? { expiresAt: result.expiresAt } : {}),
          status,
        }
      }
      if (action === 'pair') {
        const link = stringArg(args, 'link', { max: 8192 })
        const result = await instance.pair({ link })
        const status = await instance.status()
        return {
          action,
          message: `Paired with ${result?.peer?.name ?? 'the other device'}.`,
          ...(result?.peer !== undefined && typeof result.peer === 'object' ? { peer: result.peer } : {}),
          status,
        }
      }
      if (action === 'connect') {
        const deviceId = stringArg(args, 'deviceId', { max: 128, pattern: SESSION_PATTERN })
        const result = await instance.connect({ deviceId })
        const status = await instance.status()
        return {
          action,
          message: `Tunnel open; open ${result.url} in this browser to control the paired host.`,
          url: result.url,
          deviceId,
          ...(Number.isSafeInteger(result.localPort) ? { localPort: result.localPort } : {}),
          ...(Number.isSafeInteger(result.webPort) ? { webPort: result.webPort } : {}),
          status,
        }
      }
      if (action === 'disconnect') {
        const deviceId = stringArg(args, 'deviceId', { max: 128, pattern: SESSION_PATTERN })
        await instance.disconnect({ deviceId })
        const status = await instance.status()
        return { action, message: 'Tunnel closed.', status }
      }
      const deviceId = stringArg(args, 'deviceId', { max: 128, pattern: SESSION_PATTERN })
      const side = enumArg(args, 'side', ['guest', 'peer'])
      const status = await instance.unpair({ deviceId, side })
      return {
        action,
        message: side === 'guest' ? 'Device revoked.' : 'Remote host removed.',
        status,
      }
    },
  })

  // ---------------------------------------------------------------------
  // Settings page routes
  // ---------------------------------------------------------------------

  if (webServer !== undefined && connection !== undefined) {
    const rejected = (req, res) => {
      const rejection = connection.requestRejection(req)
      if (rejection === undefined) return false
      res.statusCode = rejection
      res.end()
      return true
    }

    ctx.effect(() =>
      webServer.register({
        kind: 'exact',
        path: '/dsh-connections/hosts',
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'GET') {
            res.setHeader('allow', 'GET')
            sendJson(res, 405, { code: 'method-not-allowed', message: 'GET only' })
            return
          }
          try {
            const result = await managerOf().listHosts()
            sendJson(res, 200, result)
          } catch (error) {
            sendJson(res, 500, {
              code: 'hosts-failed',
              message: error instanceof Error ? error.message : String(error),
            })
          }
        },
      }),
    )

    ctx.effect(() =>
      webServer.register({
        kind: 'exact',
        path: '/dsh-connections/test',
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'POST') {
            res.setHeader('allow', 'POST')
            sendJson(res, 405, { code: 'method-not-allowed', message: 'POST only' })
            return
          }
          const mediaType = String(req.headers['content-type'] ?? '')
            .split(';', 1)[0]
            .trim()
            .toLowerCase()
          if (mediaType !== 'application/json') {
            sendJson(res, 415, { code: 'unsupported-media-type', message: 'content-type must be application/json' })
            return
          }
          const body = await readJsonBody(req, 16 * 1024)
          if (typeof body !== 'object' || body === null || typeof body.host !== 'string') {
            sendJson(res, 400, { code: 'bad-request', message: 'body must be JSON with a string "host"' })
            return
          }
          const host = body.host
          if (host.length === 0 || host.length > 512 || !HOST_PATTERN.test(host)) {
            sendJson(res, 400, { code: 'bad-request', message: 'invalid host' })
            return
          }
          const startedAt = Date.now()
          try {
            const instance = await ready()
            const result = await instance.exec({
              host,
              command: 'echo dsh-connections-ok',
              timeoutMs: 20_000,
              maxOutputBytes: 16 * 1024,
            })
            const ok = result.exitCode === 0 && result.stdout.includes('dsh-connections-ok')
            sendJson(res, 200, {
              ok,
              host,
              ms: Date.now() - startedAt,
              ...(ok
                ? { detail: 'connection succeeded' }
                : {
                    error:
                      result.stderr.trim() ||
                      result.stdout.trim() ||
                      `ssh exited with code ${result.exitCode ?? 'null'}${result.timedOut ? ' after timeout' : ''}`,
                  }),
            })
          } catch (error) {
            sendJson(res, 200, {
              ok: false,
              host,
              ms: Date.now() - startedAt,
              error: error instanceof Error ? error.message : String(error),
            })
          }
        },
      }),
    )

    // -- device-to-device control routes ---------------------------------

    const control = async () => {
      const instance = await controlOf()
      return instance
    }

    const sendControlFailure = (res, error) => {
      const statusCode = Number.isInteger(error?.statusCode) ? error.statusCode : 400
      sendJson(res, statusCode, {
        code: typeof error?.code === 'string' ? error.code : 'control-failed',
        message: error instanceof Error ? error.message : String(error),
      })
    }

    const postJsonRoute = (path, handler) => {
      ctx.effect(() =>
        webServer.register({
          kind: 'exact',
          path,
          handler: async (req, res) => {
            if (rejected(req, res)) return
            if (req.method !== 'POST') {
              res.setHeader('allow', 'POST')
              sendJson(res, 405, { code: 'method-not-allowed', message: 'POST only' })
              return
            }
            const mediaType = String(req.headers['content-type'] ?? '')
              .split(';', 1)[0]
              .trim()
              .toLowerCase()
            if (mediaType !== 'application/json') {
              sendJson(res, 415, { code: 'unsupported-media-type', message: 'content-type must be application/json' })
              return
            }
            const body = await readJsonBody(req, 16 * 1024)
            if (typeof body !== 'object' || body === null || Array.isArray(body)) {
              sendJson(res, 400, { code: 'bad-request', message: 'body must be a JSON object' })
              return
            }
            try {
              const value = await handler(body)
              sendJson(res, 200, value)
            } catch (error) {
              sendControlFailure(res, error)
            }
          },
        }),
      )
    }

    const stringField = (body, key, max) => {
      const value = body[key]
      if (typeof value !== 'string' || value.length === 0 || value.length > max) {
        const error = new Error(`"${key}" must be a non-empty string of at most ${max} characters`)
        error.statusCode = 400
        throw error
      }
      return value
    }

    ctx.effect(() =>
      webServer.register({
        kind: 'exact',
        path: '/dsh-connections/control/status',
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'GET') {
            res.setHeader('allow', 'GET')
            sendJson(res, 405, { code: 'method-not-allowed', message: 'GET only' })
            return
          }
          try {
            sendJson(res, 200, await (await control()).status())
          } catch (error) {
            sendControlFailure(res, error)
          }
        },
      }),
    )

    postJsonRoute('/dsh-connections/control/enable', async (body) => {
      const instance = await control()
      if (typeof body.enabled !== 'boolean') {
        const error = new Error('"enabled" must be a boolean')
        error.statusCode = 400
        throw error
      }
      if (body.enabled === false) return instance.disable()
      let port
      if (body.port !== undefined && body.port !== null) {
        if (!Number.isSafeInteger(body.port) || body.port < 1024 || body.port > 65535) {
          const error = new Error('"port" must be an integer between 1024 and 65535')
          error.statusCode = 400
          throw error
        }
        port = body.port
      }
      return instance.enable(port === undefined ? {} : { port })
    })

    postJsonRoute('/dsh-connections/control/link', async () => {
      const instance = await control()
      return instance.createPairingLink()
    })

    postJsonRoute('/dsh-connections/control/pair', async (body) => {
      const instance = await control()
      const link = stringField(body, 'link', 8192)
      return instance.pair({ link })
    })

    postJsonRoute('/dsh-connections/control/connect', async (body) => {
      const instance = await control()
      const deviceId = stringField(body, 'deviceId', 128)
      return instance.connect({ deviceId })
    })

    postJsonRoute('/dsh-connections/control/disconnect', async (body) => {
      const instance = await control()
      const deviceId = stringField(body, 'deviceId', 128)
      return instance.disconnect({ deviceId })
    })

    postJsonRoute('/dsh-connections/control/unpair', async (body) => {
      const instance = await control()
      const deviceId = stringField(body, 'deviceId', 128)
      const side = body.side
      if (side !== 'guest' && side !== 'peer') {
        const error = new Error('"side" must be "guest" or "peer"')
        error.statusCode = 400
        throw error
      }
      return instance.unpair({ deviceId, side })
    })
  }

  // ---------------------------------------------------------------------
  // Model guidance
  // ---------------------------------------------------------------------

  const systemPrompt = ctx.get('systemPrompt')
  if (systemPrompt !== undefined) {
    systemPrompt.section({
      name: 'tool:ssh-connections',
      order: 120,
      text: 'Use ssh_exec for bounded remote commands, ssh_open/ssh_send/ssh_read/ssh_close for an interactive SSH session, ssh_copy to transfer files, ssh_tunnel for local port forwards, and ssh_harness to start a remote DeepSeek Harness web UI over SSH and return a localhost URL. Hosts are ~/.ssh/config aliases or user@host[:port]. Host-key trust and credentials stay with the user\'s OpenSSH setup: a first connection to an unknown host fails instead of trusting it, so the user may need a normal ssh login once. Separately, remote_control connects two DeepSeek Harness machines signed into the same DeepSeek account: status/enable/disable manage whether other devices may control this computer, pairing_link creates a one-time secret link, pair consumes it, and connect returns a localhost URL that opens the paired host\'s full Web UI through an encrypted direct tunnel. None of these paths use the cloud: both machines must reach each other over LAN/VPN and be signed in.',
    })
  }
}

// Exported for unit tests of the pure helpers without activating the plugin.
export { loadSshConfig, describeHost, parseDestination }
