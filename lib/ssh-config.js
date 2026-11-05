/**
 * Read `~/.ssh/config` (Codex-style host discovery) without touching it.
 *
 * Pure parsing plus one read-only async loader. Node builtins only; no
 * dependency on the Host runtime, so this module is unit-testable with plain
 * `node`.
 *
 * Supported: `Host` blocks with several concrete aliases, `HostName`, `User`,
 * `Port`, `IdentityFile` (leading `~` expanded), `ProxyJump`, comments,
 * quoted values, and case-insensitive keywords. Wildcard/pattern-only aliases
 * (`*`, `?`, `!`) are ignored with a warning because they cannot be offered as
 * connectable destinations. `Match` and `Include` are not interpreted.
 *
 * @module dsh-connections/ssh-config
 */

import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * @typedef {object} SshHost
 * @property {string} alias          Concrete `Host` alias from the config.
 * @property {string} [hostName]     `HostName` value (the real address).
 * @property {string} [user]         `User` value.
 * @property {number} [port]         `Port` value.
 * @property {string} [identityFile] Expanded `IdentityFile` path.
 * @property {string} [proxyJump]    `ProxyJump` value.
 * @property {'ssh-config'} source   Always `'ssh-config'`.
 */

/** @typedef {{ destination: string, host: string, user?: string, port?: number, sshArgs: string[] }} ParsedDestination */

const TILDE_LEAD = /^~(?=$|[\\/])/;

/**
 * Expand a leading `~`, `~/` or `~\` using the supplied home directory.
 * A bare `~` becomes the home directory itself; no other `~` is touched.
 *
 * @param {string} value
 * @param {string} home
 * @returns {string}
 */
export function expandHome(value, home) {
  if (typeof value !== 'string') return String(value ?? '');
  if (!TILDE_LEAD.test(value)) return value;
  const base = typeof home === 'string' ? home.replace(/[\\/]+$/, '') : '';
  const rest = value.slice(1).replace(/^[\\/]+/, '');
  if (rest === '') return base;
  if (base === '') return rest;
  const separator = base.includes('\\') && !base.includes('/') ? '\\' : '/';
  const normalizedRest =
    separator === '\\' ? rest.replace(/\//g, '\\') : rest.replace(/\\/g, '/');
  return `${base}${separator}${normalizedRest}`;
}

/**
 * Split one config line into tokens. Handles double/single quotes and inline
 * `#` comments (a `#` starts a comment only at a token boundary; `foo#bar`
 * stays literal, matching OpenSSH). Unterminated quotes keep the rest of the
 * line as the value.
 *
 * @param {string} line
 * @returns {string[]}
 */
function tokenize(line) {
  const text = stripComment(line);
  const tokens = [];
  let current = '';
  let quote = null;
  let started = false;
  const push = () => {
    if (started) tokens.push(current);
    current = '';
    started = false;
  };
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quote !== null) {
      if (char === quote) {
        quote = null;
      } else if (char === '\\' && quote === '"' && i + 1 < text.length) {
        current += text[i + 1];
        i += 1;
      } else {
        current += char;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      started = true;
      continue;
    }
    if (/\s/.test(char)) {
      push();
      continue;
    }
    current += char;
    started = true;
  }
  push();
  return tokens;
}

/**
 * Cut an inline comment without disturbing quoted text. OpenSSH only treats
 * `#` as a comment introducer at a token boundary.
 *
 * @param {string} line
 * @returns {string}
 */
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (quote !== null) {
      if (char === '\\' && quote === '"' && i + 1 < line.length) {
        i += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

/**
 * Whether a `Host` argument is a pattern rather than a concrete alias.
 *
 * @param {string} value
 * @returns {boolean}
 */
function isPatternAlias(value) {
  return /[*?!]/.test(value);
}

/**
 * Parse one `Port` value.
 *
 * @param {string} raw
 * @returns {number | undefined}
 */
function parsePort(raw) {
  if (typeof raw !== 'string' || !/^\d{1,5}$/.test(raw)) return undefined;
  const port = Number(raw);
  return port >= 1 && port <= 65535 ? port : undefined;
}

/**
 * Pure parser for ssh_config text.
 *
 * @param {string} text
 * @param {{ home?: string }} [options] Home used to expand `~` in IdentityFile
 *   (`homedir()` by default; an explicit home keeps the parser testable).
 * @returns {{ hosts: SshHost[], warnings: string[] }}
 */
export function parseSshConfig(text, options = {}) {
  const home = typeof options.home === 'string' && options.home !== '' ? options.home : homedir();
  /** @type {SshHost[]} */
  const hosts = [];
  /** @type {Map<string, SshHost>} */
  const byAlias = new Map();
  /** @type {Set<string>} */
  const warned = new Set();
  const warnings = [];
  const warn = (message) => {
    if (warned.has(message)) return;
    warned.add(message);
    warnings.push(message);
  };

  if (typeof text !== 'string') return { hosts, warnings };

  /** @type {SshHost[] | null} */
  let block = null;
  let inMatch = false;

  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  for (const rawLine of lines) {
    const tokens = tokenize(rawLine);
    if (tokens.length === 0) continue;
    const keyword = tokens[0].toLowerCase();

    if (keyword === 'host') {
      inMatch = false;
      block = [];
      const aliases = tokens.slice(1);
      if (aliases.length === 0) {
        warn('Ignored a Host block without aliases.');
        block = null;
        continue;
      }
      for (const alias of aliases) {
        if (isPatternAlias(alias)) {
          warn(`Ignored Host pattern "${alias}": wildcard aliases cannot be listed as connectable hosts.`);
          continue;
        }
        if (alias.startsWith('-')) {
          warn(`Ignored Host alias "${alias}": an alias must not start with "-".`);
          continue;
        }
        const host = /** @type {SshHost} */ ({ alias, source: 'ssh-config' });
        const existing = byAlias.get(alias);
        if (existing === undefined) {
          byAlias.set(alias, host);
          hosts.push(host);
          block.push(host);
        } else {
          // OpenSSH resolves the first matching block; later duplicates only
          // fill values the first block did not set.
          block.push(existing);
        }
      }
      if (block.length === 0) block = null;
      continue;
    }

    if (keyword === 'match') {
      inMatch = true;
      block = null;
      warn('Ignored a Match block: only Host blocks are read.');
      continue;
    }

    if (keyword === 'include') {
      warn('Ignored an Include directive: included ssh_config files are not read.');
      continue;
    }

    if (block === null || inMatch) continue;
    const value = tokens.length > 1 ? tokens[1] : '';
    if (value === '') continue;

    for (const host of block) {
      switch (keyword) {
        case 'hostname':
          if (host.hostName === undefined) host.hostName = value;
          break;
        case 'user':
          if (host.user === undefined) host.user = value;
          break;
        case 'port': {
          if (host.port !== undefined) break;
          const port = parsePort(value);
          if (port === undefined) warn(`Ignored invalid Port "${value}" for Host "${host.alias}".`);
          else host.port = port;
          break;
        }
        case 'identityfile':
          if (host.identityFile === undefined) host.identityFile = expandHome(value, home);
          break;
        case 'proxyjump':
          if (host.proxyJump === undefined) host.proxyJump = value;
          break;
        default:
          break;
      }
    }
  }

  return { hosts, warnings };
}

/**
 * Read `~/.ssh/config`. A missing or unreadable file never throws: it returns
 * `exists: false` (with a warning for read errors other than "not found").
 *
 * @param {{ home?: string, configPath?: string }} [options]
 * @returns {Promise<{ path: string, exists: boolean, hosts: SshHost[], warnings: string[] }>}
 */
export async function loadSshConfig(options = {}) {
  const home = typeof options.home === 'string' && options.home !== '' ? options.home : homedir();
  const configPath =
    typeof options.configPath === 'string' && options.configPath !== ''
      ? options.configPath
      : join(home, '.ssh', 'config');

  let text;
  try {
    text = await readFile(configPath, 'utf8');
  } catch (error) {
    const code = error !== null && typeof error === 'object' ? error.code : undefined;
    if (code === 'ENOENT' || code === 'ENOTDIR' || code === 'EISDIR') {
      return { path: configPath, exists: false, hosts: [], warnings: [] };
    }
    const detail = error instanceof Error ? error.message : String(error);
    return {
      path: configPath,
      exists: false,
      hosts: [],
      warnings: [`Could not read ${configPath}: ${detail}`],
    };
  }

  const parsed = parseSshConfig(text, { home });
  return { path: configPath, exists: true, hosts: parsed.hosts, warnings: parsed.warnings };
}

/**
 * Parse a tool-supplied destination: `alias`, `user@host`, `host:port` or
 * `user@host:port`. Bracketed IPv6 literals (`[::1]:22`) are also accepted.
 *
 * @param {string} value
 * @returns {ParsedDestination}
 * @throws {Error} on an empty/invalid destination or a port outside 1..65535.
 */
export function parseDestination(value) {
  if (typeof value !== 'string') throw new Error('destination must be a string');
  const destination = value.trim();
  if (destination === '') throw new Error('destination must not be empty');
  if (/[\u0000-\u001f\u007f]/.test(destination)) {
    throw new Error('destination must not contain control characters');
  }
  if (/\s/.test(destination)) {
    throw new Error(`invalid destination "${destination}": whitespace is not allowed`);
  }
  if (destination.startsWith('-')) {
    throw new Error(`invalid destination "${destination}": it must not start with "-"`);
  }

  let rest = destination;
  /** @type {string | undefined} */
  let user;
  const at = rest.indexOf('@');
  if (at !== -1) {
    if (rest.indexOf('@', at + 1) !== -1) {
      throw new Error(`invalid destination "${destination}": at most one "@" is allowed`);
    }
    user = rest.slice(0, at);
    rest = rest.slice(at + 1);
    if (user === '') throw new Error(`invalid destination "${destination}": the user part is empty`);
    if (user.startsWith('-')) {
      throw new Error(`invalid destination "${destination}": the user must not start with "-"`);
    }
    if (rest === '') throw new Error(`invalid destination "${destination}": the host part is empty`);
  }

  let host = rest;
  /** @type {string | undefined} */
  let port;
  let hasPort = false;
  let portText = '';

  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close === -1) {
      throw new Error(`invalid destination "${destination}": unterminated "[" in the host`);
    }
    host = rest.slice(1, close);
    const after = rest.slice(close + 1);
    if (after !== '') {
      if (!after.startsWith(':')) {
        throw new Error(`invalid destination "${destination}": expected "]" or "]:port"`);
      }
      hasPort = true;
      portText = after.slice(1);
    }
  } else {
    const firstColon = rest.indexOf(':');
    if (firstColon !== -1) {
      if (rest.indexOf(':', firstColon + 1) !== -1) {
        throw new Error(
          `invalid destination "${destination}": IPv6 addresses must be written as [host] or [host]:port`,
        );
      }
      host = rest.slice(0, firstColon);
      hasPort = true;
      portText = rest.slice(firstColon + 1);
    }
  }

  if (host === '') throw new Error(`invalid destination "${destination}": the host part is empty`);

  if (hasPort) {
    if (!/^\d{1,5}$/.test(portText)) {
      throw new Error(`invalid destination "${destination}": port "${portText}" is not a number`);
    }
    port = Number(portText);
    if (port < 1 || port > 65535) {
      throw new Error(`invalid destination "${destination}": port ${port} is outside 1..65535`);
    }
  }

  /** @type {ParsedDestination} */
  const parsed = { destination, host, sshArgs: hasPort ? ['-p', String(port)] : [] };
  if (user !== undefined) parsed.user = user;
  if (port !== undefined) parsed.port = port;
  return parsed;
}

/**
 * Human label `user@host:port`, omitting the default port (22) and any part we
 * do not know. Accepts an {@link SshHost} or a {@link parseDestination} result.
 *
 * @param {{ alias?: string, hostName?: string, host?: string, user?: string, port?: number } | null | undefined} host
 * @returns {string}
 */
export function describeHost(host) {
  if (host === null || typeof host !== 'object') return '';
  const hostPart = host.hostName ?? host.host ?? host.alias ?? '';
  const user = typeof host.user === 'string' && host.user !== '' ? host.user : undefined;
  const port = Number.isInteger(host.port) ? host.port : undefined;
  const base = user !== undefined ? `${user}@${hostPart}` : String(hostPart);
  return port !== undefined && port !== 22 ? `${base}:${port}` : base;
}
