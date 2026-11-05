/**
 * SSH connection manager for the `dsh-connections` bundle.
 *
 * A plugin-scoped value (not a service) that runs OpenSSH through the Host
 * `subprocess` service: one-shot exec, scp, interactive `ssh -tt` sessions,
 * local `-L` tunnels, and a remote DeepSeek Harness launched over SSH.
 *
 * Design rules (see the bundle contract):
 * - Every child is spawned through `subprocess.spawn`, tracked, and terminated
 *   on failure paths and on `dispose()`.
 * - `exec`/`copy` report a non-zero remote exit and a timeout in their result;
 *   they throw only for local setup problems (missing executable, bad args).
 * - `BatchMode=yes` is always set; `StrictHostKeyChecking=no` never is.
 * - No console output: an optional `log` callback receives progress lines.
 * - No secrets are recorded or returned.
 *
 * @module dsh-connections/connections
 */

import net from 'node:net';
import { homedir } from 'node:os';

import { loadSshConfig, parseDestination } from './ssh-config.js';

/** Options shared by every ssh invocation. */
const COMMON_SSH_OPTIONS = Object.freeze([
  '-o',
  'BatchMode=yes',
  '-o',
  'ConnectTimeout=15',
  '-o',
  'ServerAliveInterval=30',
]);

/** Marker used to merge captured stderr into an interactive output string. */
const STDERR_MARKER = '\n[stderr]\n';
const STDERR_MARKER_AT_START = '[stderr]\n';

/** Interactive collection caps from the contract. */
const SESSION_STDOUT_BYTES = 512 * 1024;
const SESSION_STDERR_BYTES = 64 * 1024;

/** How long an interactive session is given to produce a banner before `open` returns. */
const OPEN_SETTLE_MS = 300;

/** Graceful-exit / terminate budgets for session and tunnel teardown. */
const CLOSE_GRACE_MS = 2000;
const TERMINATE_WAIT_MS = 3000;

/** `pid` value reported when the subprocess handle exposes no OS pid (see contract note). */
const UNKNOWN_PID = 0;

/** Sentinel for a settle race that timed out without an outcome. */
const SETTLE_TIMEOUT = Symbol('settle-timeout');

/**
 * Clamp a numeric option, falling back when it is absent or unusable.
 *
 * @param {unknown} value
 * @param {number} min
 * @param {number} max
 * @param {number} fallback
 * @returns {number}
 */
function clampInt(value, min, max, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

/**
 * Validate a TCP port.
 *
 * @param {unknown} value
 * @param {string} label
 * @returns {number}
 */
function validPort(value, label) {
  const port = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${label} must be an integer between 1 and 65535`);
  }
  return port;
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Sleep for `ms`, resolving early when `signal` aborts.
 *
 * @param {number} ms
 * @param {AbortSignal} [signal]
 * @returns {Promise<void>}
 */
function sleep(ms, signal) {
  const duration = Number.isFinite(ms) ? Math.max(0, ms) : 0;
  if (duration === 0) return Promise.resolve();
  return new Promise((resolve) => {
    const finish = () => {
      clearTimeout(timer);
      if (signal !== undefined) signal.removeEventListener('abort', finish);
      resolve();
    };
    const timer = setTimeout(finish, duration);
    if (signal !== undefined) {
      if (signal.aborted) {
        finish();
        return;
      }
      signal.addEventListener('abort', finish, { once: true });
    }
  });
}

/**
 * Read (and consume) the OS pid the provider may or may not expose.
 *
 * @param {{ pid?: unknown } | null | undefined} handle
 * @returns {number}
 */
function readPid(handle) {
  const pid = handle !== null && typeof handle === 'object' ? handle.pid : undefined;
  return typeof pid === 'number' && Number.isInteger(pid) && pid > 0 ? pid : UNKNOWN_PID;
}

/**
 * One interactive SSH session (`ssh -tt`) with piped stdin and collected output.
 *
 * @typedef {object} Session
 * @property {string} sessionId
 * @property {string} host
 * @property {string | undefined} name
 * @property {any} handle
 * @property {number} stdoutOffset
 * @property {number} stderrOffset
 * @property {'running' | 'exited'} status
 * @property {number | null | undefined} exitCode
 * @property {number} pid
 * @property {string | undefined} error
 */

/**
 * One local-forward tunnel (`ssh -N -L`).
 *
 * @typedef {object} Tunnel
 * @property {string} tunnelId
 * @property {string} host
 * @property {number} localPort
 * @property {string} remoteHost
 * @property {number} remotePort
 * @property {number} pid
 * @property {any} handle
 * @property {boolean} exited
 * @property {number | null | undefined} exitCode
 * @property {string | undefined} error
 */

/**
 * One recorded remote DeepSeek Harness launch.
 *
 * @typedef {object} HarnessRecord
 * @property {string} key
 * @property {string} host
 * @property {string} profile
 * @property {number} remotePort
 * @property {number} localPort
 * @property {string} tunnelId
 * @property {number} pid
 * @property {string} logPath
 * @property {number} startedAt
 */

/**
 * SSH lifecycle for the plugin. Create once per plugin context and call
 * `dispose()` from the plugin's teardown.
 */
export class ConnectionManager {
  /** @type {any} */
  #subprocess;
  /** @type {string} */
  #home;
  /** @type {number} */
  #maxOutputBytes;
  /** @type {number} */
  #execTimeoutMs;
  /** @type {((line: string) => void) | undefined} */
  #log;

  /** @type {string | undefined} */
  #ssh;
  /** @type {string | undefined} */
  #scp;
  /** @type {Promise<{ ssh: string, scp: string | undefined }> | undefined} */
  #initPromise;
  #disposed = false;

  /** @type {Map<string, Session>} */
  #sessions = new Map();
  /** @type {Map<string, { closed: true, exitCode: number | null }>} */
  #closedSessions = new Map();
  /** @type {Map<string, Tunnel>} */
  #tunnels = new Map();
  /** @type {Map<string, HarnessRecord>} */
  #harnessRecords = new Map();
  /** @type {Set<any>} */
  #live = new Set();
  #sshSeq = 0;
  #tunnelSeq = 0;

  /**
   * @param {{ subprocess: any, home?: string, maxOutputBytes?: number, execTimeoutMs?: number, log?: (line: string) => void }} options
   */
  constructor(options) {
    const opts = options ?? {};
    if (opts.subprocess === undefined || opts.subprocess === null) {
      throw new TypeError('ConnectionManager requires the Host subprocess service (options.subprocess)');
    }
    if (typeof opts.subprocess.spawn !== 'function') {
      throw new TypeError('ConnectionManager requires options.subprocess.spawn');
    }
    this.#subprocess = opts.subprocess;
    this.#home =
      typeof opts.home === 'string' && opts.home !== '' ? opts.home : homedir();
    this.#maxOutputBytes = clampInt(opts.maxOutputBytes, 1024, 4 * 1024 * 1024, 64 * 1024);
    this.#execTimeoutMs = clampInt(opts.execTimeoutMs, 1000, 60 * 60 * 1000, 120_000);
    this.#log = typeof opts.log === 'function' ? opts.log : undefined;
  }

  /**
   * Resolve `ssh` once (`scp` best-effort). Throws a readable Error when the
   * OpenSSH client is missing.
   *
   * @returns {Promise<{ ssh: string, scp: string | undefined }>}
   */
  async init() {
    this.#assertUsable();
    if (this.#initPromise === undefined) {
      this.#initPromise = this.#resolveExecutables().catch((error) => {
        this.#initPromise = undefined;
        throw error;
      });
    }
    return this.#initPromise;
  }

  /** @returns {Promise<{ ssh: string, scp: string | undefined }>} */
  async #resolveExecutables() {
    let ssh;
    try {
      ssh = await this.#subprocess.resolveExecutable('ssh');
    } catch (error) {
      throw new Error(
        `dsh-connections: the OpenSSH client (ssh) is not available on this machine: ${errorMessage(error)}`,
      );
    }
    if (typeof ssh !== 'string' || ssh === '') {
      throw new Error(
        'dsh-connections: the OpenSSH client (ssh) is not available on this machine; install the Windows OpenSSH client or add ssh to PATH',
      );
    }

    let scp;
    try {
      const resolved = await this.#subprocess.resolveExecutable('scp');
      scp = typeof resolved === 'string' && resolved !== '' ? resolved : undefined;
    } catch {
      scp = undefined;
    }

    this.#ssh = ssh;
    this.#scp = scp;
    this.#emit(`ssh executable: ${ssh}`);
    if (scp === undefined) this.#emit('scp executable not found; ssh_copy will be unavailable');
    return { ssh, scp };
  }

  /**
   * Hosts from `~/.ssh/config`.
   *
   * @returns {Promise<{ path: string, exists: boolean, hosts: import('./ssh-config.js').SshHost[], warnings: string[] }>}
   */
  async listHosts() {
    this.#assertUsable();
    const result = await loadSshConfig({ home: this.#home });
    for (const warning of result.warnings) this.#emit(`ssh config: ${warning}`);
    return result;
  }

  /**
   * One-shot remote command (`ssh -T`, no PTY, BatchMode). Resolves for a
   * non-zero remote exit and marks timeouts; throws only for local problems.
   *
   * @param {{ host: string, command: string, timeoutMs?: number, maxOutputBytes?: number, signal?: AbortSignal }} params
   * @returns {Promise<{ host: string, command: string, exitCode: number | null, signal: string | null, stdout: string, stderr: string, truncated: boolean, timedOut: boolean, durationMs: number }>}
   */
  async exec({ host, command, timeoutMs = this.#execTimeoutMs, maxOutputBytes, signal } = {}) {
    this.#assertUsable();
    if (typeof command !== 'string' || command.trim() === '') {
      throw new Error('exec: "command" must be a non-empty string');
    }
    return this.#execCommand({ host, command, timeoutMs, maxOutputBytes, signal });
  }

  /**
   * One scp transfer.
   *
   * @param {{ host: string, direction: 'upload' | 'download', localPath: string, remotePath: string, recursive?: boolean, timeoutMs?: number, signal?: AbortSignal }} params
   * @returns {Promise<{ ok: boolean, direction: 'upload' | 'download', exitCode: number | null, stderr: string, durationMs: number }>}
   */
  async copy({
    host,
    direction,
    localPath,
    remotePath,
    recursive = false,
    timeoutMs = this.#execTimeoutMs,
    signal,
  } = {}) {
    this.#assertUsable();
    if (direction !== 'upload' && direction !== 'download') {
      throw new Error('copy: "direction" must be "upload" or "download"');
    }
    if (typeof localPath !== 'string' || localPath === '') {
      throw new Error('copy: "localPath" must be a non-empty string');
    }
    if (typeof remotePath !== 'string' || remotePath === '') {
      throw new Error('copy: "remotePath" must be a non-empty string');
    }

    await this.init();
    if (this.#scp === undefined) {
      throw new Error(
        'copy: scp was not found on this machine; install the Windows OpenSSH client (scp.exe) or use exec with a remote command',
      );
    }
    const target = this.#target(host);
    const scp = this.#scp;
    const argv = [scp];
    if (recursive) argv.push('-r');
    argv.push('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15');
    if (target.port !== undefined) argv.push('-P', String(target.port));
    const remote = `${target.target}:${remotePath}`;
    if (direction === 'upload') argv.push(localPath, remote);
    else argv.push(remote, localPath);
    const startedAt = Date.now();
    const deadline = this.#deadline(timeoutMs, signal);
    let handle;
    try {
      handle = this.#spawnTracked({
        argv,
        cwd: this.#home,
        stdio: {
          stdin: 'ignore',
          stdout: { maxBytes: this.#maxOutputBytes },
          stderr: { maxBytes: this.#maxOutputBytes },
        },
        graceMs: 5000,
        signal: deadline.signal,
      });
    } catch (error) {
      deadline.cleanup();
      throw new Error(`copy: could not start scp for "${host}": ${errorMessage(error)}`);
    }

    const settled = await this.#awaitOutcome(handle, deadline.ms + 10_000);
    const timedOut = deadline.timedOut() || settled.stalled === true;
    deadline.cleanup();

    if (settled.stalled === true) {
      try {
        handle.terminate();
      } catch {
        // ignore
      }
    } else if (settled.failure !== undefined && !timedOut) {
      try {
        handle.terminate();
      } catch {
        // ignore
      }
      throw new Error(`copy: scp process failed for "${host}": ${errorMessage(settled.failure)}`);
    }

    const stderr = this.#readCollected(handle, 'stderr', 0);
    let stderrText = stderr.text;
    if (timedOut && stderrText.trim() === '') {
      stderrText = `scp timed out after ${deadline.ms}ms`;
    }
    return {
      ok: !timedOut && settled.outcome?.exitCode === 0,
      direction,
      exitCode: settled.outcome?.exitCode ?? null,
      stderr: stderrText,
      durationMs: Date.now() - startedAt,
    };
  }

  /**
   * Open an interactive SSH session (`ssh -tt`) with piped stdin.
   *
   * @param {{ host: string, name?: string }} params
   * @returns {Promise<{ sessionId: string, host: string, pid: number, status: 'running', initialOutput: string }>}
   */
  async open({ host, name } = {}) {
    this.#assertUsable();
    await this.init();
    const target = this.#target(host);
    const argv = [this.#ssh, '-tt', ...COMMON_SSH_OPTIONS, ...target.sshArgs, target.target];

    /** @type {Session} */
    const session = {
      sessionId: `ssh-${++this.#sshSeq}`,
      host: target.destination,
      name: this.#normalizeName(name),
      handle: undefined,
      stdoutOffset: 0,
      stderrOffset: 0,
      status: 'running',
      exitCode: undefined,
      pid: UNKNOWN_PID,
      error: undefined,
    };

    try {
      session.handle = this.#spawnTracked({
        argv,
        cwd: this.#home,
        stdio: {
          stdin: 'pipe',
          stdout: { maxBytes: SESSION_STDOUT_BYTES },
          stderr: { maxBytes: SESSION_STDERR_BYTES },
        },
        graceMs: 5000,
      });
    } catch (error) {
      throw new Error(`open: could not start ssh for "${target.destination}": ${errorMessage(error)}`);
    }

    session.pid = readPid(session.handle);
    this.#sessions.set(session.sessionId, session);
    session.handle.done.then(
      (outcome) => {
        session.status = 'exited';
        session.exitCode = outcome?.exitCode ?? null;
      },
      (error) => {
        session.status = 'exited';
        session.exitCode = null;
        session.error = errorMessage(error);
      },
    ).catch(() => {});

    await sleep(OPEN_SETTLE_MS);
    const initial = this.#sessionDelta(session);
    this.#emit(
      `opened ${session.sessionId} to ${target.destination}${session.name === undefined ? '' : ` (${session.name})`}`,
    );
    return {
      sessionId: session.sessionId,
      host: session.host,
      pid: session.pid,
      status: 'running',
      initialOutput: initial.output,
    };
  }

  /**
   * Write to an interactive session, wait `waitMs`, and return the new output.
   *
   * @param {{ sessionId: string, text: string, submit?: boolean, waitMs?: number, signal?: AbortSignal }} params
   * @returns {Promise<{ sessionId: string, output: string, truncated: boolean, status: 'running' | 'exited', exitCode: number | null }>}
   */
  async send({ sessionId, text, submit = true, waitMs = 1500, signal } = {}) {
    this.#assertUsable();
    const session = this.#requireSession(sessionId);
    if (typeof text !== 'string') throw new Error('send: "text" must be a string');
    if (session.status !== 'running') {
      throw new Error(`send: SSH session "${sessionId}" is not running (${session.status})`);
    }
    const stream = session.handle?.stdin;
    if (stream === undefined || stream === null) {
      throw new Error(`send: SSH session "${sessionId}" has no stdin pipe`);
    }

    const payload = submit ? `${text}\r` : text;
    try {
      await this.#writeStdin(stream, payload);
    } catch (error) {
      throw new Error(`send: could not write to SSH session "${sessionId}": ${errorMessage(error)}`);
    }

    await sleep(clampInt(waitMs, 0, 30_000, 1500), signal);
    const delta = this.#sessionDelta(session);
    // `exitCode` is always present (null while running): the tool schema is
    // nullable-and-required, so callers never have to test for absence.
    return {
      sessionId,
      output: delta.output,
      truncated: delta.truncated,
      status: session.status,
      exitCode: session.status === 'exited' ? session.exitCode ?? null : null,
    };
  }

  /**
   * Return buffered output not yet returned to the caller for this session.
   *
   * @param {{ sessionId: string }} params
   * @returns {{ sessionId: string, output: string, truncated: boolean, status: 'running' | 'exited', exitCode: number | null }}
   */
  read({ sessionId } = {}) {
    this.#assertUsable();
    const session = this.#requireSession(sessionId);
    const delta = this.#sessionDelta(session);
    return {
      sessionId,
      output: delta.output,
      truncated: delta.truncated,
      status: session.status,
      exitCode: session.status === 'exited' ? session.exitCode ?? null : null,
    };
  }

  /**
   * Gracefully exit an interactive session, then terminate it. Idempotent.
   *
   * @param {{ sessionId: string }} params
   * @returns {Promise<{ sessionId: string, closed: true, exitCode: number | null }>}
   */
  async close({ sessionId } = {}) {
    this.#assertUsable();
    if (typeof sessionId !== 'string' || sessionId === '') {
      throw new Error('close: "sessionId" must be a non-empty string');
    }
    const closed = this.#closedSessions.get(sessionId);
    if (closed !== undefined) {
      return { sessionId, closed: true, exitCode: closed.exitCode };
    }
    const session = this.#sessions.get(sessionId);
    if (session === undefined) throw new Error(`close: unknown SSH session "${sessionId}"`);

    const handle = session.handle;
    let exitCode = session.exitCode ?? null;
    try {
      if (session.status === 'running' && handle.stdin !== undefined) {
        try {
          await this.#writeStdin(handle.stdin, 'exit\r');
        } catch {
          // The remote side may already be gone; termination below settles it.
        }
        const outcome = await this.#settleOutcome(handle, CLOSE_GRACE_MS);
        if (outcome !== undefined) exitCode = outcome.exitCode ?? null;
      }
    } finally {
      try {
        handle.terminate();
      } catch {
        // terminate() is documented idempotent; a throw here must not mask close.
      }
      await this.#settleOutcome(handle, TERMINATE_WAIT_MS);
      this.#sessions.delete(sessionId);
      this.#closedSessions.set(sessionId, { closed: true, exitCode });
    }
    this.#emit(`closed ${sessionId}`);
    return { sessionId, closed: true, exitCode };
  }

  /**
   * Active interactive sessions.
   *
   * @returns {Array<{ sessionId: string, host: string, name?: string, pid: number, status: 'running' | 'exited', exitCode: number | null }>}
   */
  sessions() {
    this.#assertUsable();
    /** @type {Array<{ sessionId: string, host: string, name?: string, pid: number, status: 'running' | 'exited', exitCode: number | null }>} */
    const result = [];
    for (const session of this.#sessions.values()) {
      const entry = {
        sessionId: session.sessionId,
        host: session.host,
        pid: session.pid,
        status: session.status,
        exitCode: session.status === 'exited' ? session.exitCode ?? null : null,
      };
      if (session.name !== undefined) entry.name = session.name;
      result.push(entry);
    }
    return result;
  }

  /**
   * Open a local forward (`ssh -N -L`), waiting until the local port accepts TCP.
   *
   * @param {{ host: string, remoteHost?: string, remotePort: number, localPort?: number, readyTimeoutMs?: number }} params
   * @returns {Promise<{ tunnelId: string, host: string, localPort: number, remoteHost: string, remotePort: number, pid: number, localUrl: string }>}
   */
  async tunnelOpen({
    host,
    remoteHost = '127.0.0.1',
    remotePort,
    localPort = 0,
    readyTimeoutMs = 15000,
  } = {}) {
    this.#assertUsable();
    await this.init();
    const target = this.#target(host);
    const remotePortNumber = validPort(remotePort, 'remotePort');
    if (typeof remoteHost !== 'string' || remoteHost.trim() === '') {
      throw new Error('tunnelOpen: "remoteHost" must be a non-empty string');
    }
    const wantedLocalPort =
      localPort === undefined || localPort === null || localPort === 0
        ? 0
        : validPort(localPort, 'localPort');
    const boundLocalPort = wantedLocalPort === 0 ? await this.#freePort() : wantedLocalPort;

    const forward = `127.0.0.1:${boundLocalPort}:${remoteHost}:${remotePortNumber}`;
    const argv = [
      this.#ssh,
      '-N',
      ...COMMON_SSH_OPTIONS,
      '-o',
      'ExitOnForwardFailure=yes',
      '-L',
      forward,
      ...target.sshArgs,
      target.target,
    ];

    /** @type {Tunnel} */
    const tunnel = {
      tunnelId: `tunnel-${++this.#tunnelSeq}`,
      host: target.destination,
      localPort: boundLocalPort,
      remoteHost,
      remotePort: remotePortNumber,
      pid: UNKNOWN_PID,
      handle: undefined,
      exited: false,
      exitCode: undefined,
      error: undefined,
    };

    try {
      tunnel.handle = this.#spawnTracked({
        argv,
        cwd: this.#home,
        stdio: {
          stdin: 'ignore',
          stdout: { maxBytes: this.#maxOutputBytes },
          stderr: { maxBytes: this.#maxOutputBytes },
        },
        graceMs: 5000,
      });
    } catch (error) {
      throw new Error(`tunnelOpen: could not start ssh for "${target.destination}": ${errorMessage(error)}`);
    }

    tunnel.pid = readPid(tunnel.handle);
    this.#tunnels.set(tunnel.tunnelId, tunnel);
    tunnel.handle.done.then(
      (outcome) => {
        tunnel.exited = true;
        tunnel.exitCode = outcome?.exitCode ?? null;
      },
      (error) => {
        tunnel.exited = true;
        tunnel.exitCode = null;
        tunnel.error = errorMessage(error);
      },
    ).catch(() => {});

    const ready = await this.#waitForTcp(
      boundLocalPort,
      clampInt(readyTimeoutMs, 1000, 120_000, 15000),
      () => tunnel.exited,
    );
    if (ready === false) {
      try {
        tunnel.handle.terminate();
      } catch {
        // ignore
      }
      await this.#settleOutcome(tunnel.handle, TERMINATE_WAIT_MS);
      this.#tunnels.delete(tunnel.tunnelId);
      const stderr = this.#readCollected(tunnel.handle, 'stderr', 0).text;
      throw this.#sshFailure(
        `tunnelOpen: ssh tunnel to ${target.destination} (127.0.0.1:${boundLocalPort} -> ${remoteHost}:${remotePortNumber}) did not become ready`,
        target.destination,
        stderr,
        tunnel,
      );
    }

    this.#emit(
      `opened ${tunnel.tunnelId}: 127.0.0.1:${boundLocalPort} -> ${target.destination}:${remoteHost}:${remotePortNumber}`,
    );
    return {
      tunnelId: tunnel.tunnelId,
      host: target.destination,
      localPort: boundLocalPort,
      remoteHost,
      remotePort: remotePortNumber,
      pid: tunnel.pid,
      localUrl: `http://127.0.0.1:${boundLocalPort}/`,
    };
  }

  /**
   * Live tunnels.
   *
   * @returns {Array<{ tunnelId: string, host: string, localPort: number, remoteHost: string, remotePort: number, pid: number }>}
   */
  tunnelList() {
    this.#assertUsable();
    /** @type {Array<{ tunnelId: string, host: string, localPort: number, remoteHost: string, remotePort: number, pid: number }>} */
    const result = [];
    for (const tunnel of this.#tunnels.values()) {
      if (tunnel.exited) continue;
      result.push({
        tunnelId: tunnel.tunnelId,
        host: tunnel.host,
        localPort: tunnel.localPort,
        remoteHost: tunnel.remoteHost,
        remotePort: tunnel.remotePort,
        pid: tunnel.pid,
      });
    }
    return result;
  }

  /**
   * Close one tunnel (also works on the record of a tunnel that already
   * exited).
   *
   * @param {{ tunnelId: string }} params
   * @returns {Promise<{ tunnelId: string, closed: true }>}
   */
  async tunnelClose({ tunnelId } = {}) {
    this.#assertUsable();
    if (typeof tunnelId !== 'string' || tunnelId === '') {
      throw new Error('tunnelClose: "tunnelId" must be a non-empty string');
    }
    const tunnel = this.#tunnels.get(tunnelId);
    if (tunnel === undefined) throw new Error(`tunnelClose: unknown tunnel "${tunnelId}"`);
    try {
      tunnel.handle.terminate();
    } catch {
      // ignore
    }
    await this.#settleOutcome(tunnel.handle, TERMINATE_WAIT_MS);
    this.#tunnels.delete(tunnelId);
    for (const [key, record] of this.#harnessRecords) {
      if (record.tunnelId === tunnelId) this.#harnessRecords.delete(key);
    }
    this.#emit(`closed ${tunnelId}`);
    return { tunnelId, closed: true };
  }

  /**
   * Status/start/stop a remote DeepSeek Harness over SSH.
   *
   * `start` launches `dsh --profile <profile> --no-open --port <remotePort>
   * --host 127.0.0.1` under nohup, forwards it to a local port (the remote port
   * by default, so a same-port OAuth callback works), waits for HTTP readiness,
   * and returns the local URL.
   *
   * @param {{ host: string, action: 'status' | 'start' | 'stop', profile?: string, remotePort?: number, localPort?: number, readyTimeoutMs?: number }} params
   * @returns {Promise<{ action: string, host: string, installed: boolean, version?: string, running: boolean, remotePort?: number, localPort?: number, url?: string, pid?: number, logPath?: string, message: string }>}
   */
  async harness({
    host,
    action,
    profile = 'web',
    remotePort = 39001,
    localPort,
    readyTimeoutMs = 60000,
  } = {}) {
    this.#assertUsable();
    await this.init();
    if (action !== 'status' && action !== 'start' && action !== 'stop') {
      throw new Error('harness: "action" must be "status", "start" or "stop"');
    }
    const target = this.#target(host);
    if (typeof profile !== 'string' || !/^[A-Za-z0-9._-]+$/.test(profile)) {
      throw new Error('harness: "profile" may contain only letters, digits, ".", "_" and "-"');
    }
    const port = validPort(remotePort, 'remotePort');
    const key = this.#harnessKey(target.destination, profile, port);

    if (action === 'status') return this.#harnessStatus(target, profile, port, key);
    if (action === 'stop') return this.#harnessStop(target, profile, port, key);
    return this.#harnessStart({ target, profile, remotePort: port, key, localPort, readyTimeoutMs });
  }

  /**
   * Terminate all tunnels, sessions and tracked child handles. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    const handles = new Set(this.#live);
    for (const session of this.#sessions.values()) handles.add(session.handle);
    for (const tunnel of this.#tunnels.values()) handles.add(tunnel.handle);
    for (const handle of handles) {
      try {
        handle.terminate();
      } catch {
        // keep disposing the rest
      }
    }
    await Promise.allSettled([...handles].map((handle) => this.#settleOutcome(handle, TERMINATE_WAIT_MS)));
    this.#sessions.clear();
    this.#closedSessions.clear();
    this.#tunnels.clear();
    this.#harnessRecords.clear();
    this.#live.clear();
    this.#emit('disposed: all SSH children terminated');
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /** @returns {void} */
  #assertUsable() {
    if (this.#disposed) throw new Error('dsh-connections: the SSH connection manager has been disposed');
  }

  /**
   * @param {string} line
   * @returns {void}
   */
  #emit(line) {
    if (this.#log === undefined) return;
    try {
      this.#log(line);
    } catch {
      // A logging callback must never break the connection flow.
    }
  }

  /**
   * Normalize an optional session name.
   *
   * @param {unknown} name
   * @returns {string | undefined}
   */
  #normalizeName(name) {
    if (typeof name !== 'string') return undefined;
    const trimmed = name.trim();
    return trimmed === '' ? undefined : trimmed.slice(0, 80);
  }

  /**
   * @param {string} host
   * @returns {{ destination: string, host: string, user?: string, port?: number, sshArgs: string[], target: string }}
   */
  #target(host) {
    if (typeof host !== 'string' || host.trim() === '') {
      throw new Error('host must be a non-empty SSH alias or user@host[:port]');
    }
    let parsed;
    try {
      parsed = parseDestination(host);
    } catch (error) {
      throw new Error(`invalid host "${host}": ${errorMessage(error)}`);
    }
    return {
      destination: parsed.destination,
      host: parsed.host,
      user: parsed.user,
      port: parsed.port,
      sshArgs: parsed.sshArgs,
      target: parsed.user === undefined ? parsed.host : `${parsed.user}@${parsed.host}`,
    };
  }

  /**
   * Spawn through the Host service and track the handle for `dispose()`.
   *
   * @param {any} spec
   * @returns {any}
   */
  #spawnTracked(spec) {
    const handle = this.#subprocess.spawn(spec);
    this.#live.add(handle);
    const release = () => {
      this.#live.delete(handle);
    };
    handle.done.then(release, release).catch(() => {});
    return handle;
  }

  /**
   * Combine a deadline timer with the caller's abort signal into one signal.
   *
   * @param {unknown} timeoutMs
   * @param {AbortSignal} [signal]
   * @returns {{ signal: AbortSignal, timedOut: () => boolean, ms: number, cleanup: () => void }}
   */
  #deadline(timeoutMs, signal) {
    const ms = clampInt(timeoutMs, 1, 60 * 60 * 1000, this.#execTimeoutMs);
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort(new Error('operation timed out'));
    }, ms);
    const onAbort = () => {
      controller.abort(signal?.reason);
    };
    if (signal !== undefined) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    return {
      signal: controller.signal,
      timedOut: () => timedOut,
      ms,
      cleanup() {
        clearTimeout(timer);
        if (signal !== undefined) signal.removeEventListener('abort', onAbort);
      },
    };
  }

  /**
   * Await `handle.done` without letting a rejection escape, bounded so a
   * provider that never settles cannot hang a tool call. A `stalled` result
   * means the bound expired first; the caller decides how to terminate.
   *
   * @param {any} handle
   * @param {number} boundMs
   * @returns {Promise<{ outcome?: { exitCode: number | null, signal: string | null }, failure?: unknown, stalled?: boolean }>}
   */
  async #awaitOutcome(handle, boundMs) {
    let timer;
    const bound = new Promise((resolve) => {
      timer = setTimeout(() => resolve({ stalled: true }), Math.max(1000, boundMs));
    });
    const settled = await Promise.race([
      handle.done.then(
        (outcome) => ({ outcome }),
        (failure) => ({ failure }),
      ),
      bound,
    ]);
    clearTimeout(timer);
    return settled;
  }

  /**
   * Await an outcome with a bound; returns undefined when the bound expires.
   *
   * @param {any} handle
   * @param {number} ms
   * @returns {Promise<{ exitCode: number | null, signal: string | null } | undefined>}
   */
  async #settleOutcome(handle, ms) {
    let timer;
    const bound = new Promise((resolve) => {
      timer = setTimeout(() => resolve(SETTLE_TIMEOUT), Math.max(1, ms));
    });
    try {
      const settled = await Promise.race([handle.done, bound]);
      return settled === SETTLE_TIMEOUT ? undefined : settled;
    } catch {
      return undefined;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Read one collected stream without throwing.
   *
   * @param {any} handle
   * @param {'stdout' | 'stderr'} name
   * @param {number} fromOffset
   * @returns {{ text: string, nextOffset: number, truncated: boolean }}
   */
  #readCollected(handle, name, fromOffset) {
    try {
      const reader = handle?.collected?.[name];
      if (reader === undefined || reader === null || typeof reader.readFrom !== 'function') {
        return { text: '', nextOffset: fromOffset, truncated: false };
      }
      const read = reader.readFrom(fromOffset);
      return {
        text: typeof read?.text === 'string' ? read.text : '',
        nextOffset: Number.isFinite(read?.nextOffset) ? read.nextOffset : fromOffset,
        truncated: read?.lossy === true || read?.truncated === true,
      };
    } catch {
      return { text: '', nextOffset: fromOffset, truncated: false };
    }
  }

  /**
   * Read the interactive deltas since the session cursors and merge stderr in.
   *
   * @param {Session} session
   * @returns {{ output: string, truncated: boolean }}
   */
  #sessionDelta(session) {
    const stdout = this.#readCollected(session.handle, 'stdout', session.stdoutOffset);
    session.stdoutOffset = stdout.nextOffset;
    const stderr = this.#readCollected(session.handle, 'stderr', session.stderrOffset);
    session.stderrOffset = stderr.nextOffset;

    let output = stdout.text;
    if (stderr.text !== '') {
      output = output === ''
        ? `${STDERR_MARKER_AT_START}${stderr.text}`
        : `${output}${STDERR_MARKER}${stderr.text}`;
    }
    return { output, truncated: stdout.truncated || stderr.truncated };
  }

  /**
   * @param {unknown} sessionId
   * @returns {Session}
   */
  #requireSession(sessionId) {
    if (typeof sessionId !== 'string' || sessionId === '') {
      throw new Error('sessionId must be a non-empty string');
    }
    const session = this.#sessions.get(sessionId);
    if (session !== undefined) return session;
    if (this.#closedSessions.has(sessionId)) {
      throw new Error(`SSH session "${sessionId}" is already closed`);
    }
    throw new Error(`Unknown SSH session "${sessionId}"; open one with ssh_open first`);
  }

  /**
   * Write to a session stdin and wait until the stream acknowledges the write.
   *
   * @param {any} stream
   * @param {string} data
   * @returns {Promise<void>}
   */
  async #writeStdin(stream, data) {
    await new Promise((resolve, reject) => {
      let settled = false;
      const onError = (error) => {
        if (settled) return;
        settled = true;
        try {
          stream.off?.('error', onError);
        } catch {
          // ignore
        }
        reject(error);
      };
      try {
        stream.once?.('error', onError);
        stream.write(data, (error) => {
          if (settled) return;
          settled = true;
          try {
            stream.off?.('error', onError);
          } catch {
            // ignore
          }
          if (error) reject(error);
          else resolve();
        });
      } catch (error) {
        onError(error);
      }
    });
  }

  /**
   * Run one ssh command and shape the contract result.
   *
   * @param {{ host: string, command: string, timeoutMs?: number, maxOutputBytes?: number, signal?: AbortSignal }} params
   * @returns {Promise<{ host: string, command: string, exitCode: number | null, signal: string | null, stdout: string, stderr: string, truncated: boolean, timedOut: boolean, durationMs: number }>}
   */
  async #execCommand({ host, command, timeoutMs, maxOutputBytes, signal }) {
    await this.init();
    const target = this.#target(host);
    const cap = clampInt(maxOutputBytes, 1024, 4 * 1024 * 1024, this.#maxOutputBytes);
    const argv = [this.#ssh, '-T', ...COMMON_SSH_OPTIONS, ...target.sshArgs, target.target, command];
    const startedAt = Date.now();
    const deadline = this.#deadline(timeoutMs, signal);

    let handle;
    try {
      handle = this.#spawnTracked({
        argv,
        cwd: this.#home,
        stdio: {
          stdin: 'ignore',
          stdout: { maxBytes: cap },
          stderr: { maxBytes: cap },
        },
        graceMs: 5000,
        signal: deadline.signal,
      });
    } catch (error) {
      deadline.cleanup();
      throw new Error(`exec: could not start ssh for "${target.destination}": ${errorMessage(error)}`);
    }

    const settled = await this.#awaitOutcome(handle, deadline.ms + 10_000);
    const timedOut = deadline.timedOut() || settled.stalled === true;
    deadline.cleanup();

    if (settled.stalled === true) {
      try {
        handle.terminate();
      } catch {
        // ignore
      }
    } else if (settled.failure !== undefined && !timedOut) {
      try {
        handle.terminate();
      } catch {
        // ignore
      }
      throw new Error(`exec: ssh process failed for "${target.destination}": ${errorMessage(settled.failure)}`);
    }

    const stdout = this.#readCollected(handle, 'stdout', 0);
    const stderr = this.#readCollected(handle, 'stderr', 0);
    return {
      host: target.destination,
      command,
      exitCode: settled.outcome?.exitCode ?? null,
      signal: settled.outcome?.signal ?? null,
      stdout: stdout.text,
      stderr: stderr.text,
      truncated: stdout.truncated || stderr.truncated,
      timedOut,
      durationMs: Date.now() - startedAt,
    };
  }

  /**
   * Turn captured ssh stderr into an actionable error (host key, auth, DNS).
   *
   * @param {string} summary
   * @param {string} host
   * @param {string} stderr
   * @param {{ exited?: boolean } | undefined} [state]
   * @returns {Error}
   */
  #sshFailure(summary, host, stderr, state) {
    const detail = (stderr ?? '').trim();
    let hint = '';
    if (/host key verification failed/i.test(detail)) {
      hint = `ssh: host key verification failed for "${host}"; run \`ssh ${host}\` once in a terminal to accept the host key`;
    } else if (/permission denied/i.test(detail)) {
      hint = `ssh: authentication failed for "${host}"; BatchMode=yes disables password prompts, so check your key (IdentityFile) or ssh-agent`;
    } else if (/could not resolve hostname/i.test(detail)) {
      hint = `ssh: cannot resolve the address of "${host}"; check HostName in ~/.ssh/config`;
    } else if (/address already in use|bind/i.test(detail)) {
      hint = `the local port is already in use; stop the other program or choose a different localPort`;
    } else if (/connection (refused|timed out)|network is unreachable|no route to host/i.test(detail)) {
      hint = `ssh: cannot reach "${host}"; the host may be offline, or a firewall/VPN may be required`;
    } else if (state?.exited === true) {
      hint = `ssh exited before the forward became ready`;
    } else {
      hint = `the local port never accepted a connection`;
    }
    const parts = [summary, hint];
    if (detail !== '') parts.push(`ssh said: ${detail}`);
    return new Error(parts.join('; '));
  }

  /**
   * TCP connect probe.
   *
   * @param {number} port
   * @param {number} timeoutMs
   * @returns {Promise<boolean>}
   */
  async #tcpProbe(port, timeoutMs) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(ok);
      };
      const socket = net.connect({ host: '127.0.0.1', port });
      socket.setTimeout(Math.max(50, timeoutMs));
      socket.once('connect', () => finish(true));
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));
    });
  }

  /**
   * Poll `127.0.0.1:port` until it accepts TCP, the timeout expires, or the
   * tunnel child exits.
   *
   * @param {number} port
   * @param {number} timeoutMs
   * @param {() => boolean} hasExited
   * @returns {Promise<boolean>}
   */
  async #waitForTcp(port, timeoutMs, hasExited) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (hasExited()) return false;
      const budget = Math.max(100, Math.min(1000, deadline - Date.now()));
      if (await this.#tcpProbe(port, budget)) return true;
      if (hasExited()) return false;
      await sleep(Math.min(200, Math.max(0, deadline - Date.now())));
    }
    return false;
  }

  /**
   * Allocate a free local port on 127.0.0.1.
   *
   * @returns {Promise<number>}
   */
  async #freePort() {
    return new Promise((resolve, reject) => {
      const server = net.createServer();
      server.unref();
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        const port = typeof address === 'object' && address !== null ? address.port : 0;
        server.close(() => {
          if (port > 0) resolve(port);
          else reject(new Error('could not allocate a free local port'));
        });
      });
    });
  }

  /**
   * Whether a local port can be bound right now.
   *
   * @param {number} port
   * @returns {Promise<boolean>}
   */
  async #portAvailable(port) {
    return new Promise((resolve) => {
      const server = net.createServer();
      server.unref();
      server.once('error', () => resolve(false));
      server.listen(port, '127.0.0.1', () => {
        server.close(() => resolve(true));
      });
    });
  }

  /**
   * Poll an HTTP endpoint; any HTTP status counts as ready.
   *
   * @param {number} port
   * @param {number} timeoutMs
   * @param {() => boolean} hasExited
   * @returns {Promise<boolean>}
   */
  async #waitForHttp(port, timeoutMs, hasExited) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (hasExited()) return false;
      try {
        const response = await fetch(`http://127.0.0.1:${port}/`, {
          signal: AbortSignal.timeout(4000),
          redirect: 'manual',
        });
        try {
          await response.body?.cancel();
        } catch {
          // body already consumed/closed
        }
        return true;
      } catch {
        // not listening yet
      }
      if (hasExited()) return false;
      await sleep(500);
    }
    return false;
  }

  /**
   * `probe` the remote `dsh` binary and its version.
   *
   * @param {string} host
   * @returns {Promise<{ installed: boolean, version?: string, error?: string }>}
   */
  async #probeInstall(host) {
    const command =
      'sh -lc \'if command -v dsh >/dev/null 2>&1; then printf "installed\\n"; dsh --version 2>/dev/null | head -n 1; else printf "missing\\n"; fi\'';
    let result;
    try {
      result = await this.#execCommand({
        host,
        command,
        timeoutMs: 15_000,
        maxOutputBytes: 8 * 1024,
      });
    } catch (error) {
      return { installed: false, error: errorMessage(error) };
    }
    if (result.timedOut) return { installed: false, error: 'the remote probe timed out' };
    if (result.exitCode !== 0) {
      const detail = (result.stderr || result.stdout).trim().split(/\r?\n/)[0] ?? '';
      return {
        installed: false,
        error: detail === '' ? `the remote probe exited with code ${result.exitCode}` : detail,
      };
    }
    const lines = result.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== '');
    if (lines[0] === 'installed') {
      const version = lines.find((line) => line !== 'installed');
      return version === undefined ? { installed: true } : { installed: true, version };
    }
    if (lines[0] === 'missing') return { installed: false };
    return { installed: false, error: 'unexpected probe output from the remote shell' };
  }

  /**
   * @param {string} host
   * @param {string} profile
   * @param {number} remotePort
   * @returns {string}
   */
  #harnessKey(host, profile, remotePort) {
    return `${host}\u0000${profile}\u0000${remotePort}`;
  }

  /**
   * @param {string} tunnelId
   * @returns {boolean}
   */
  #tunnelAlive(tunnelId) {
    const tunnel = this.#tunnels.get(tunnelId);
    return tunnel !== undefined && !tunnel.exited;
  }

  /**
   * @param {string} host
   * @param {number} pid
   * @returns {Promise<boolean>}
   */
  async #remotePidAlive(host, pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
      const result = await this.#execCommand({
        host,
        command: `sh -lc 'kill -0 ${pid} 2>/dev/null && printf "alive\\n" || printf "gone\\n"'`,
        timeoutMs: 15_000,
        maxOutputBytes: 1024,
      });
      return !result.timedOut && result.stdout.includes('alive');
    } catch {
      return false;
    }
  }

  /**
   * @param {string} host
   * @param {number} pid
   * @returns {Promise<void>}
   */
  async #killRemotePid(host, pid) {
    if (!Number.isInteger(pid) || pid <= 0) return;
    try {
      await this.#execCommand({
        host,
        command: `sh -lc 'kill ${pid} 2>/dev/null || true'`,
        timeoutMs: 15_000,
        maxOutputBytes: 1024,
      });
    } catch {
      // best effort
    }
  }

  /**
   * @param {string} host
   * @param {string} relativePath
   * @returns {Promise<string>}
   */
  async #readRemoteLogTail(host, relativePath) {
    try {
      const result = await this.#execCommand({
        host,
        command: `sh -lc 'tail -n 20 "$HOME/${relativePath}" 2>/dev/null || true'`,
        timeoutMs: 15_000,
        maxOutputBytes: 8 * 1024,
      });
      return result.stdout.trim().slice(0, 4000);
    } catch {
      return '';
    }
  }

  /**
   * @param {{ destination: string }} target
   * @param {string} profile
   * @param {number} remotePort
   * @param {string} key
   * @returns {Promise<object>}
   */
  async #harnessStatus(target, profile, remotePort, key) {
    const probe = await this.#probeInstall(target.destination);
    const record = this.#harnessRecords.get(key);
    const live = record !== undefined && this.#tunnelAlive(record.tunnelId);

    /** @type {{ action: string, host: string, installed: boolean, version?: string, running: boolean, remotePort?: number, localPort?: number, url?: string, pid?: number, logPath?: string, message: string }} */
    const result = {
      action: 'status',
      host: target.destination,
      installed: probe.installed,
      running: live,
      message: '',
    };
    if (probe.version !== undefined) result.version = probe.version;

    if (live && record !== undefined) {
      result.remotePort = record.remotePort;
      result.localPort = record.localPort;
      result.url = `http://127.0.0.1:${record.localPort}/`;
      result.pid = record.pid;
      result.logPath = record.logPath;
      result.message = `remote dsh (profile ${record.profile}) is recorded as running on ${target.destination}:${record.remotePort}; open ${result.url}`;
      return result;
    }

    if (record !== undefined) {
      if (!live) {
        try {
          await this.tunnelClose({ tunnelId: record.tunnelId });
        } catch {
          // the forward was already gone
        }
      }
      this.#harnessRecords.delete(key);
    }

    if (!probe.installed) {
      result.message =
        probe.error === undefined
          ? `dsh is not installed on ${target.destination}; install DeepSeek Harness there first`
          : `could not verify dsh on ${target.destination}: ${probe.error}`;
    } else {
      const suffix = probe.version === undefined ? '' : ` (${probe.version})`;
      result.message = `dsh is installed on ${target.destination}${suffix}; no remote harness (profile ${profile}, port ${remotePort}) is recorded as running`;
    }
    return result;
  }

  /**
   * @param {{ destination: string }} target
   * @param {string} profile
   * @param {number} remotePort
   * @param {string} key
   * @returns {Promise<object>}
   */
  async #harnessStop(target, profile, remotePort, key) {
    const record = this.#harnessRecords.get(key);
    if (record === undefined) {
      return {
        action: 'stop',
        host: target.destination,
        installed: false,
        running: false,
        message: `no remote dsh (profile ${profile}, port ${remotePort}) is recorded for ${target.destination}`,
      };
    }

    let killConfirmed = true;
    let killDetail = '';
    try {
      const result = await this.#execCommand({
        host: target.destination,
        command: `sh -lc 'kill ${record.pid} 2>/dev/null || true'`,
        timeoutMs: 15_000,
        maxOutputBytes: 1024,
      });
      if (result.timedOut) {
        killConfirmed = false;
        killDetail = 'the remote kill timed out';
      } else if (result.exitCode !== 0) {
        killConfirmed = false;
        killDetail = (result.stderr || result.stdout).trim().split(/\r?\n/)[0] ?? '';
      }
    } catch (error) {
      killConfirmed = false;
      killDetail = errorMessage(error);
    }

    let tunnelClosed = true;
    try {
      await this.tunnelClose({ tunnelId: record.tunnelId });
    } catch {
      tunnelClosed = false;
    }
    this.#harnessRecords.delete(key);

    const notes = [];
    if (!killConfirmed) {
      notes.push(
        `remote pid ${record.pid} could not be confirmed killed${killDetail === '' ? '' : ` (${killDetail})`}; it may still be running`,
      );
    }
    if (!tunnelClosed) notes.push('the local forward was already gone');

    /** @type {{ action: string, host: string, installed: boolean, running: boolean, remotePort?: number, localPort?: number, pid?: number, logPath?: string, message: string }} */
    const result = {
      action: 'stop',
      host: target.destination,
      installed: true,
      running: false,
      remotePort: record.remotePort,
      localPort: record.localPort,
      pid: record.pid,
      logPath: record.logPath,
      message:
        `stopped dsh (profile ${record.profile}) on ${target.destination}:${record.remotePort} and closed the local forward` +
        (notes.length === 0 ? '' : `; ${notes.join('; ')}`),
    };
    this.#emit(`harness stopped on ${target.destination}:${record.remotePort}`);
    return result;
  }

  /**
   * @param {{ target: { destination: string }, profile: string, remotePort: number, key: string, localPort?: number, readyTimeoutMs: number }} params
   * @returns {Promise<object>}
   */
  async #harnessStart({ target, profile, remotePort, key, localPort, readyTimeoutMs }) {
    const existing = this.#harnessRecords.get(key);
    if (existing !== undefined) {
      const alive = await this.#remotePidAlive(target.destination, existing.pid);
      if (alive && this.#tunnelAlive(existing.tunnelId)) {
        return this.#harnessResult('start', target.destination, existing, true);
      }
      try {
        await this.tunnelClose({ tunnelId: existing.tunnelId });
      } catch {
        // already gone
      }
      this.#harnessRecords.delete(key);
    }

    const probe = await this.#probeInstall(target.destination);
    if (!probe.installed) {
      return {
        action: 'start',
        host: target.destination,
        installed: false,
        running: false,
        remotePort,
        message:
          probe.error === undefined
            ? `dsh is not installed on ${target.destination}; install DeepSeek Harness there first`
            : `could not verify dsh on ${target.destination}: ${probe.error}`,
      };
    }

    const requestedLocalPort =
      localPort === undefined || localPort === null || localPort === 0
        ? remotePort
        : validPort(localPort, 'localPort');
    const chosenLocalPort = (await this.#portAvailable(requestedLocalPort))
      ? requestedLocalPort
      : await this.#freePort();

    const logRelativePath = `.dsh-connections/dsh-${profile}-${remotePort}.log`;
    const command = [
      'sh -lc',
      `'mkdir -p "$HOME/.dsh-connections" &&`,
      `nohup dsh --profile ${profile} --no-open --port ${remotePort} --host 127.0.0.1`,
      `> "$HOME/${logRelativePath}" 2>&1 < /dev/null & echo $!'`,
    ].join(' ');

    let startResult;
    try {
      startResult = await this.#execCommand({
        host: target.destination,
        command,
        timeoutMs: 30_000,
        maxOutputBytes: 8 * 1024,
      });
    } catch (error) {
      throw new Error(`harness: could not start dsh on ${target.destination}: ${errorMessage(error)}`);
    }
    if (startResult.timedOut || startResult.exitCode !== 0) {
      const detail = (startResult.stderr || startResult.stdout).trim();
      throw new Error(
        `harness: could not start dsh on ${target.destination}${detail === '' ? '' : `: ${detail}`}`,
      );
    }
    const pid = this.#parseStartPid(startResult.stdout);
    if (pid === undefined) {
      const detail = startResult.stderr.trim();
      throw new Error(
        `harness: dsh start on ${target.destination} did not report a process id${detail === '' ? '' : `: ${detail}`}`,
      );
    }

    const overallDeadline = Date.now() + clampInt(readyTimeoutMs, 5000, 180_000, 60_000);
    let tunnelId;
    try {
      const tunnel = await this.tunnelOpen({
        host: target.destination,
        remoteHost: '127.0.0.1',
        remotePort,
        localPort: chosenLocalPort,
        readyTimeoutMs: Math.max(1000, Math.min(15_000, overallDeadline - Date.now())),
      });
      tunnelId = tunnel.tunnelId;
      const ready = await this.#waitForHttp(
        chosenLocalPort,
        Math.max(1000, overallDeadline - Date.now()),
        () => !this.#tunnelAlive(tunnelId),
      );
      if (!ready) {
        throw new Error(
          `the local forward on 127.0.0.1:${chosenLocalPort} never answered an HTTP request`,
        );
      }
    } catch (error) {
      await this.#killRemotePid(target.destination, pid);
      if (tunnelId !== undefined) {
        try {
          await this.tunnelClose({ tunnelId });
        } catch {
          // already gone
        }
      }
      const tail = await this.#readRemoteLogTail(target.destination, logRelativePath);
      throw new Error(
        `harness: remote dsh did not become ready on ${target.destination}:${remotePort} (${errorMessage(error)})` +
          (tail === ''
            ? `; remote log: $HOME/${logRelativePath}`
            : `\nremote log $HOME/${logRelativePath}:\n${tail}`),
      );
    }

    /** @type {HarnessRecord} */
    const record = {
      key,
      host: target.destination,
      profile,
      remotePort,
      localPort: chosenLocalPort,
      tunnelId,
      pid,
      logPath: `$HOME/${logRelativePath}`,
      startedAt: Date.now(),
    };
    this.#harnessRecords.set(key, record);

    const message =
      chosenLocalPort === remotePort
        ? `started dsh (profile ${profile}) on ${target.destination}:${remotePort}; open http://127.0.0.1:${chosenLocalPort}/`
        : `started dsh (profile ${profile}) on ${target.destination}:${remotePort}; local port ${remotePort} was busy, so the forward is http://127.0.0.1:${chosenLocalPort}/`;
    this.#emit(`harness started on ${target.destination}:${remotePort} (pid ${pid})`);
    return this.#harnessResult('start', target.destination, record, true, message, probe.version);
  }

  /**
   * @param {string} action
   * @param {string} host
   * @param {HarnessRecord} record
   * @param {boolean} running
   * @param {string} [message]
   * @param {string} [version]
   * @returns {object}
   */
  #harnessResult(action, host, record, running, message, version) {
    /** @type {{ action: string, host: string, installed: boolean, version?: string, running: boolean, remotePort?: number, localPort?: number, url?: string, pid?: number, logPath?: string, message: string }} */
    const result = {
      action,
      host,
      installed: true,
      running,
      remotePort: record.remotePort,
      localPort: record.localPort,
      url: `http://127.0.0.1:${record.localPort}/`,
      pid: record.pid,
      logPath: record.logPath,
      message:
        message ??
        `remote dsh (profile ${record.profile}) is already running on ${host}:${record.remotePort}; open http://127.0.0.1:${record.localPort}/`,
    };
    if (version !== undefined) result.version = version;
    return result;
  }

  /**
   * Parse the pid echoed by the nohup launcher.
   *
   * @param {string} stdout
   * @returns {number | undefined}
   */
  #parseStartPid(stdout) {
    const lines = String(stdout ?? '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^\d+$/.test(line));
    const last = lines.at(-1);
    if (last === undefined) return undefined;
    const pid = Number(last);
    return Number.isInteger(pid) && pid > 0 ? pid : undefined;
  }
}
