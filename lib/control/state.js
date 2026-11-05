/**
 * Persistent device-control state and the pairing-link codec.
 *
 * All functions in this module are plain helpers: nothing runs at import time,
 * every function is explicit about the `DSH_HOME` it uses, and the module only
 * touches the filesystem inside `loadState`/`saveState`.
 *
 * State file: `${DSH_HOME|~/.dsh}/connections/control.json` (mode 0600, written
 * atomically via a temporary file in the same directory followed by rename).
 *
 * The pairing link is a bearer secret (it embeds the guest PSK). Decoding
 * validates every field strictly; encoding never logs or echoes the payload.
 *
 * @module dsh-connections/control/state
 */

import { randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { homedir, hostname, networkInterfaces } from 'node:os';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';

/** On-disk schema version. */
export const STATE_VERSION = 1;

/** Prefix of a copy/paste pairing link. */
export const PAIRING_LINK_PREFIX = 'dshconn://pair/';

/** `kind` discriminator carried inside a pairing payload. */
export const PAIRING_LINK_KIND = 'dsh-connections-pair';

/** Default TLS listener port for "control this computer". */
export const DEFAULT_CONTROL_PORT = 39_002;

/** Upper bound for a pasted link; protects the routes and the parser. */
export const PAIRING_LINK_MAX_LENGTH = 8_192;

/** How long the UI advertises a generated link (the host invalidates on next link). */
export const PAIRING_LINK_TTL_MS = 24 * 60 * 60 * 1_000;

/** Name stored for a device that has not completed its first handshake yet. */
export const PENDING_DEVICE_NAME = '等待配对';

/** 32 random bytes, base64url (no padding) — the PSK format. */
const PSK_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const DEVICE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const MAX_DEVICE_ID_LENGTH = 128;
const MAX_NAME_LENGTH = 64;
const MAX_ACCOUNT_ID_LENGTH = 256;
const MAX_ADDRESSES = 16;
const CONTROL_DIR_NAME = 'connections';
const STATE_FILE_NAME = 'control.json';

/**
 * Error type carrying a stable machine-readable code for the HTTP layer.
 */
export class StateError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'state-error') {
    super(message);
    this.name = 'StateError';
    this.code = code;
  }
}

/**
 * Resolve the DSH home directory for this state file.
 *
 * @param {string} [home] Explicit override (tests, non-default profiles).
 * @returns {string}
 */
export function resolveHome(home) {
  if (typeof home === 'string' && home.trim() !== '') return resolve(home);
  const fromEnv = process.env.DSH_HOME;
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return resolve(fromEnv);
  return join(homedir(), '.dsh');
}

/**
 * Absolute path of the control state file.
 *
 * @param {string} [home]
 * @returns {string}
 */
export function stateFilePath(home) {
  return join(resolveHome(home), CONTROL_DIR_NAME, STATE_FILE_NAME);
}

/**
 * Create a fresh 32-byte PSK as base64url (43 chars, no padding).
 *
 * @returns {string}
 */
export function newPsk() {
  return randomBytes(32).toString('base64url');
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isPsk(value) {
  if (typeof value !== 'string' || !PSK_PATTERN.test(value)) return false;
  try {
    return Buffer.from(value, 'base64url').length === 32;
  } catch {
    return false;
  }
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isDeviceId(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_DEVICE_ID_LENGTH &&
    DEVICE_ID_PATTERN.test(value)
  );
}

/**
 * Collapse a device/account label to a safe, bounded single line.
 *
 * @param {unknown} value
 * @param {string} [fallback]
 * @returns {string}
 */
export function sanitizeDeviceName(value, fallback = '') {
  if (typeof value !== 'string') return fallback;
  const collapsed = value
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (collapsed === '') return fallback;
  return collapsed.slice(0, MAX_NAME_LENGTH);
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isPort(value) {
  return Number.isInteger(value) && value >= 1 && value <= 65_535;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isAddress(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 64 && isIP(value) !== 0;
}

/**
 * Generate (or complete) this device's identity.
 *
 * @param {{ id?: string, name?: string }} [options]
 * @returns {{ id: string, name: string }}
 */
export function createDeviceIdentity(options = {}) {
  const id = typeof options.id === 'string' && options.id !== '' ? options.id : randomUUID();
  if (!isDeviceId(id)) throw new StateError('设备 ID 无效。', 'bad-device-id');
  const name = sanitizeDeviceName(options.name ?? hostname(), 'DSH');
  return { id, name };
}

/**
 * A brand-new, empty state document.
 *
 * @param {{ id?: string, name?: string }} [identity]
 * @returns {object}
 */
export function defaultState(identity = {}) {
  return {
    version: STATE_VERSION,
    thisDevice: createDeviceIdentity(identity),
    host: {
      enabled: false,
      port: DEFAULT_CONTROL_PORT,
      pending: {},
      paired: {},
    },
    peers: {},
  };
}

/**
 * Coerce untrusted on-disk JSON into the current state shape.
 *
 * Invalid individual records are dropped rather than throwing, so one bad row
 * can never make the whole control feature unusable. The returned value is a
 * fresh object (safe to mutate before `saveState`).
 *
 * @param {unknown} raw
 * @param {{ id?: string, name?: string }} [fallbackIdentity]
 * @returns {object}
 */
export function normalizeState(raw, fallbackIdentity = {}) {
  const source = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const state = defaultState(fallbackIdentity);

  const identity = source.thisDevice;
  if (identity !== null && typeof identity === 'object') {
    if (isDeviceId(identity.id)) state.thisDevice.id = identity.id;
    state.thisDevice.name = sanitizeDeviceName(identity.name, state.thisDevice.name);
  }

  const host = source.host;
  if (host !== null && typeof host === 'object') {
    state.host.enabled = host.enabled === true;
    if (isPort(host.port)) state.host.port = host.port;
    state.host.pending = normalizePending(host.pending);
    state.host.paired = normalizePaired(host.paired);
  }

  const peers = source.peers;
  if (peers !== null && typeof peers === 'object' && !Array.isArray(peers)) {
    for (const [deviceId, value] of Object.entries(peers)) {
      const peer = normalizePeer(deviceId, value);
      if (peer !== undefined) state.peers[deviceId] = peer;
    }
  }

  return state;
}

/**
 * @param {unknown} value
 * @returns {Record<string, object>}
 */
function normalizePending(value) {
  const out = {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const [deviceId, record] of Object.entries(value)) {
    if (!isDeviceId(deviceId)) continue;
    if (record === null || typeof record !== 'object') continue;
    if (!isPsk(record.psk)) continue;
    out[deviceId] = {
      psk: record.psk,
      name: sanitizeDeviceName(record.name, PENDING_DEVICE_NAME),
      createdAt: finiteTimestamp(record.createdAt),
    };
  }
  return out;
}

/**
 * @param {unknown} value
 * @returns {Record<string, object>}
 */
function normalizePaired(value) {
  const out = {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const [deviceId, record] of Object.entries(value)) {
    if (!isDeviceId(deviceId)) continue;
    if (record === null || typeof record !== 'object') continue;
    if (!isPsk(record.psk)) continue;
    out[deviceId] = {
      psk: record.psk,
      name: sanitizeDeviceName(record.name, '已配对设备'),
      accountId: sanitizeAccountId(record.accountId),
      pairedAt: finiteTimestamp(record.pairedAt),
      lastSeenAt: finiteTimestamp(record.lastSeenAt),
    };
  }
  return out;
}

/**
 * @param {string} deviceId
 * @param {unknown} value
 * @returns {object | undefined}
 */
function normalizePeer(deviceId, value) {
  if (!isDeviceId(deviceId)) return undefined;
  if (value === null || typeof value !== 'object') return undefined;
  if (!isPsk(value.psk)) return undefined;
  const addresses = normalizeAddresses(value.addresses);
  return {
    deviceId,
    guestId: isDeviceId(value.guestId) ? value.guestId : '',
    name: sanitizeDeviceName(value.name, '远程设备'),
    addresses: addresses.length > 0 ? addresses : ['127.0.0.1'],
    port: isPort(value.port) ? value.port : DEFAULT_CONTROL_PORT,
    psk: value.psk,
    accountId: sanitizeAccountId(value.accountId),
    webPort: isPort(value.webPort) ? value.webPort : 0,
    pairedAt: finiteTimestamp(value.pairedAt),
    lastConnectedAt: finiteTimestamp(value.lastConnectedAt),
  };
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function finiteTimestamp(value) {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.trunc(number);
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function sanitizeAccountId(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.length > MAX_ACCOUNT_ID_LENGTH) return '';
  return trimmed.replace(/[\u0000-\u001f\u007f\s]/g, '');
}

/**
 * De-duplicate and order addresses: usable addresses first, `127.0.0.1` last.
 *
 * @param {unknown} value
 * @returns {string[]}
 */
export function normalizeAddresses(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const regular = [];
  let loopback = false;
  for (const entry of value) {
    if (!isAddress(entry)) continue;
    if (entry === '127.0.0.1' || entry === '::1') {
      loopback = true;
      continue;
    }
    if (seen.has(entry)) continue;
    seen.add(entry);
    regular.push(entry);
    if (regular.length >= MAX_ADDRESSES - 1) break;
  }
  if (loopback) regular.push('127.0.0.1');
  return regular;
}

/**
 * Local non-internal IPv4 addresses, with `127.0.0.1` last.
 *
 * @param {ReturnType<typeof networkInterfaces>} [interfaces] Injectable for tests.
 * @returns {string[]}
 */
export function listAddresses(interfaces = networkInterfaces()) {
  const addresses = [];
  const seen = new Set();
  for (const entries of Object.values(interfaces ?? {})) {
    for (const entry of entries ?? []) {
      if (entry === null || typeof entry !== 'object') continue;
      const family = typeof entry.family === 'string' ? entry.family : String(entry.family);
      if (family !== 'IPv4' && family !== '4') continue;
      if (entry.internal === true) continue;
      if (!isAddress(entry.address)) continue;
      if (entry.address.startsWith('169.254.')) continue;
      if (entry.address === '127.0.0.1') continue;
      if (seen.has(entry.address)) continue;
      seen.add(entry.address);
      addresses.push(entry.address);
    }
  }
  addresses.push('127.0.0.1');
  return addresses;
}

/**
 * Load state from disk, creating the default document when it does not exist.
 *
 * Throws `StateError` when the file exists but cannot be parsed, so callers can
 * decide whether to surface it or reset to a fresh state.
 *
 * @param {{ home?: string, name?: string }} [options]
 * @returns {Promise<object>}
 */
export async function loadState(options = {}) {
  const file = stateFilePath(options.home);
  let text;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return defaultState({ name: options.name });
    throw new StateError(`无法读取控制状态文件（${error?.code ?? 'unknown'}）。`, 'state-read-failed');
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new StateError('控制状态文件不是有效的 JSON，可能已损坏。', 'state-corrupt');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new StateError('控制状态文件格式无效。', 'state-corrupt');
  }
  if (parsed.version !== undefined && parsed.version !== STATE_VERSION) {
    throw new StateError('控制状态文件版本不受支持。', 'state-version');
  }
  return normalizeState(parsed, { name: options.name });
}

/**
 * Persist state atomically with owner-only permissions.
 *
 * @param {object} state
 * @param {{ home?: string }} [options]
 * @returns {Promise<object>} the normalized document that was written
 */
export async function saveState(state, options = {}) {
  const file = stateFilePath(options.home);
  const normalized = normalizeState(state);
  const directory = dirname(file);
  const temporary = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;

  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(temporary, `${JSON.stringify(normalized, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await rename(temporary, file);
    // Best effort: Windows ignores POSIX modes, POSIX backends tighten here.
    await chmod(file, 0o600).catch(() => {});
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw new StateError(`无法保存控制状态（${error?.code ?? 'unknown'}）。`, 'state-write-failed');
  }

  return normalized;
}

/**
 * Build a pairing link from its parts. Throws on invalid input; never logs.
 *
 * @param {{ accountId: string, host: { id: string, name: string, addresses: string[], port: number }, guest: { id: string, psk: string }, createdAt?: number }} payload
 * @returns {string}
 */
export function encodePairingLink(payload) {
  if (payload === null || typeof payload !== 'object') {
    throw new StateError('配对链接数据无效。', 'bad-link');
  }
  const accountId = sanitizeAccountId(payload.accountId);
  if (accountId === '') throw new StateError('配对链接缺少账号标识。', 'bad-link');

  const host = payload.host;
  if (host === null || typeof host !== 'object') throw new StateError('配对链接缺少主机信息。', 'bad-link');
  if (!isDeviceId(host.id)) throw new StateError('配对链接中的主机设备 ID 无效。', 'bad-link');
  const addresses = normalizeAddresses(host.addresses);
  if (addresses.length === 0) throw new StateError('配对链接缺少可用的主机地址。', 'bad-link');
  if (!isPort(host.port)) throw new StateError('配对链接中的主机端口无效。', 'bad-link');

  const guest = payload.guest;
  if (guest === null || typeof guest !== 'object') throw new StateError('配对链接缺少配对设备信息。', 'bad-link');
  if (!isDeviceId(guest.id)) throw new StateError('配对链接中的配对设备 ID 无效。', 'bad-link');
  if (!isPsk(guest.psk)) throw new StateError('配对链接中的设备密钥无效。', 'bad-link');
  if (guest.id === host.id) throw new StateError('配对链接不能指向本机自身。', 'bad-link');

  const createdAt = finiteTimestamp(payload.createdAt ?? Date.now());
  const document = {
    v: STATE_VERSION,
    kind: PAIRING_LINK_KIND,
    accountId,
    host: {
      id: host.id,
      name: sanitizeDeviceName(host.name, 'DSH'),
      addresses,
      port: host.port,
    },
    guest: { id: guest.id, psk: guest.psk },
    createdAt,
  };
  return PAIRING_LINK_PREFIX + Buffer.from(JSON.stringify(document), 'utf8').toString('base64url');
}

/**
 * Decode and strictly validate a pairing link.
 *
 * @param {unknown} link
 * @returns {{ v: 1, kind: string, accountId: string, host: { id: string, name: string, addresses: string[], port: number }, guest: { id: string, psk: string }, createdAt: number }}
 */
export function decodePairingLink(link) {
  if (typeof link !== 'string') {
    throw new StateError('配对链接必须是字符串。', 'bad-link');
  }
  const value = link.trim();
  if (value === '') throw new StateError('配对链接为空。', 'bad-link');
  if (value.length > PAIRING_LINK_MAX_LENGTH) {
    throw new StateError('配对链接过长，不是有效的 DSH 配对链接。', 'bad-link');
  }
  if (!value.startsWith(PAIRING_LINK_PREFIX)) {
    throw new StateError('配对链接格式无效：应以 dshconn://pair/ 开头。', 'bad-link');
  }

  const encoded = value.slice(PAIRING_LINK_PREFIX.length);
  if (encoded === '' || !BASE64URL_PATTERN.test(encoded) || encoded.length % 4 === 1) {
    throw new StateError('配对链接内容无效。', 'bad-link');
  }
  let document;
  try {
    const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
    // Reject non-canonical encodings so links are byte-identical to what we emit.
    if (Buffer.from(decoded, 'utf8').toString('base64url') !== encoded) {
      throw new Error('not canonical');
    }
    document = JSON.parse(decoded);
  } catch {
    throw new StateError('配对链接内容无效或已损坏。', 'bad-link');
  }

  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    throw new StateError('配对链接内容无效。', 'bad-link');
  }
  if (document.v !== STATE_VERSION) {
    throw new StateError('配对链接版本不受支持，请升级 DSH。', 'bad-link');
  }
  if (document.kind !== PAIRING_LINK_KIND) {
    throw new StateError('这不是 DSH 设备控制配对链接。', 'bad-link');
  }

  const accountId = sanitizeAccountId(document.accountId);
  if (accountId === '') throw new StateError('配对链接缺少账号标识。', 'bad-link');

  const host = document.host;
  if (host === null || typeof host !== 'object') throw new StateError('配对链接缺少主机信息。', 'bad-link');
  if (!isDeviceId(host.id)) throw new StateError('配对链接中的主机设备 ID 无效。', 'bad-link');
  const addresses = normalizeAddresses(host.addresses);
  if (addresses.length === 0) throw new StateError('配对链接缺少可用的主机地址。', 'bad-link');
  if (!isPort(host.port)) throw new StateError('配对链接中的主机端口无效。', 'bad-link');

  const guest = document.guest;
  if (guest === null || typeof guest !== 'object') throw new StateError('配对链接缺少配对设备信息。', 'bad-link');
  if (!isDeviceId(guest.id)) throw new StateError('配对链接中的配对设备 ID 无效。', 'bad-link');
  if (!isPsk(guest.psk)) throw new StateError('配对链接中的设备密钥无效。', 'bad-link');
  if (guest.id === host.id) throw new StateError('配对链接无效：设备与主机相同。', 'bad-link');

  return {
    v: STATE_VERSION,
    kind: PAIRING_LINK_KIND,
    accountId,
    host: {
      id: host.id,
      name: sanitizeDeviceName(host.name, 'DSH'),
      addresses,
      port: host.port,
    },
    guest: { id: guest.id, psk: guest.psk },
    createdAt: finiteTimestamp(document.createdAt),
  };
}
