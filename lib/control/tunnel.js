/**
 * Encrypted peer-channel primitives and the one-line control handshake.
 *
 * The Harness host runs on Electron/BoringSSL, which does not provide OpenSSL
 * TLS-PSK ciphers, so the transport is a small dependency-free AES-256-GCM
 * channel over plain TCP:
 *
 * 1. The client sends `"DSHCONN1"` + identity length + identity + a 32-byte
 *    client nonce; the host looks up the paired device's 32-byte PSK by
 *    identity (an unknown identity gets the socket closed without a reply).
 * 2. The host replies `"DSHCONN1"` + a 32-byte server nonce. Both sides derive
 *    one key per direction with HKDF-SHA256 over the PSK and both nonces.
 * 3. The client sends an encrypted `{"type":"auth"}` frame (counter 0); the
 *    host verifies it and replies with an encrypted `{"type":"auth-ok"}` frame.
 *    Only then does `connectPsk` resolve / `onConnection` run, so a wrong key,
 *    an unknown identity or a non-PSK peer never reaches the HTTP layer.
 *
 * After the handshake, frames are `[uint32 length][uint32 counter][ciphertext]
 * [16-byte GCM tag]` with AAD = the 8-byte header. A zero-length payload is a
 * clean FIN. Counters are strict and independent per direction.
 *
 * The one-line control protocol on top of the channel (newline-terminated JSON,
 * ≤ 8192 bytes):
 * - `{"op":"hello","name":"Laptop","accountId":"..."}` → `{"ok":true,"host":{...},"webPort":N}`
 * - `{"op":"auth-url"}` → `{"ok":true,"url":"...","webPort":N}`
 * - `{"op":"proxy"}` → `{"ok":true}` then the channel becomes a raw byte pipe.
 * - failures → `{"ok":false,"error":"..."}` then close.
 *
 * This module never logs PSKs, nonces, tags or tokens; callers get opaque bytes.
 *
 * @module dsh-connections/control/tunnel
 */

import net from 'node:net';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { Duplex } from 'node:stream';

/** First control line cap. */
export const CONTROL_LINE_MAX_BYTES = 8_192;

/** HTTP request/response head cap for the rewrite proxy. */
export const HTTP_HEAD_MAX_BYTES = 64 * 1024;

/** Time budget for the first control line. */
export const HANDSHAKE_TIMEOUT_MS = 10_000;

/** Time budget for an HTTP head. */
export const HEAD_TIMEOUT_MS = 30_000;

/** Time budget for a TCP + channel handshake to a peer. */
export const CONNECT_TIMEOUT_MS = 8_000;

/** Fixed protocol prefix carried by both handshake messages. */
const CHANNEL_MAGIC = Buffer.from('DSHCONN1', 'ascii');

/** Nonce size for both sides. */
const NONCE_BYTES = 32;

/** Maximum UTF-8 byte length of a device identity. */
const MAX_IDENTITY_BYTES = 128;

/** Maximum encrypted payload per frame. */
const MAX_FRAME_BYTES = 64 * 1024;

/** AES-GCM tag length. */
const TAG_BYTES = 16;

/** Precomputed auth payloads (never secret). */
const AUTH_PAYLOAD = Buffer.from('{"type":"auth"}', 'utf8');
const AUTH_OK_PAYLOAD = Buffer.from('{"type":"auth-ok"}', 'utf8');

/**
 * Tunnel/protocol failure with a machine-readable code and no secrets.
 */
export class TunnelError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   * @param {Error} [cause]
   */
  constructor(message, code = 'tunnel-error', cause) {
    super(message);
    this.name = 'TunnelError';
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Reduce an error to a safe, bounded protocol response string.
 *
 * @param {unknown} error
 * @returns {string}
 */
export function safeErrorText(error) {
  const text = errorMessage(error === undefined ? 'unknown error' : error)
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .trim();
  return text.slice(0, 300) || 'unknown error';
}

/**
 * Derive the two directional keys from the PSK and both nonces.
 *
 * @param {Buffer} psk
 * @param {Buffer} clientNonce
 * @param {Buffer} serverNonce
 * @returns {{ c2s: Buffer, s2c: Buffer }}
 */
function deriveKeys(psk, clientNonce, serverNonce) {
  const salt = Buffer.concat([clientNonce, serverNonce]);
  const c2s = Buffer.from(hkdfSync('sha256', psk, salt, Buffer.from('dsh-connections c2s v1'), 32));
  const s2c = Buffer.from(hkdfSync('sha256', psk, salt, Buffer.from('dsh-connections s2c v1'), 32));
  return { c2s, s2c };
}

/**
 * Encrypt one frame.
 *
 * @param {Buffer} key
 * @param {number} counter
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function encryptFrame(key, counter, payload) {
  const header = Buffer.allocUnsafe(8);
  header.writeUInt32BE(payload.length, 0);
  header.writeUInt32BE(counter >>> 0, 4);
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(0, 0);
  iv.writeUInt32BE(counter >>> 0, 4);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(header);
  const body = Buffer.concat([cipher.update(payload), cipher.final()]);
  return Buffer.concat([header, body, cipher.getAuthTag()]);
}

/**
 * Decrypt one frame's body.
 *
 * @param {Buffer} key
 * @param {number} counter
 * @param {Buffer} header
 * @param {Buffer} body
 * @param {Buffer} tag
 * @returns {Buffer}
 */
function decryptFrame(key, counter, header, body, tag) {
  if (tag.length !== TAG_BYTES) throw new TunnelError('加密帧无效。', 'bad-frame');
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(0, 0);
  iv.writeUInt32BE(counter >>> 0, 4);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/**
 * Byte/frame reader used only during the handshake. It may over-read; the
 * leftover buffer is handed to `SecureChannel` once the handshake completes.
 */
class HandshakeReader {
  /** @param {import('node:net').Socket} socket */
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
    this.failure = undefined;
    this.ended = false;
    this.onData = (chunk) => {
      this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
      this.flush();
    };
    this.onError = (error) => {
      this.failure = error instanceof Error ? error : new Error(String(error));
      this.flush();
    };
    this.onEnd = () => {
      this.ended = true;
      this.flush();
    };
    this.onClose = () => {
      this.ended = true;
      this.flush();
    };
    socket.on('data', this.onData);
    socket.once('error', this.onError);
    socket.once('end', this.onEnd);
    socket.once('close', this.onClose);
  }

  flush() {
    if (this.waiters.length === 0) return;
    if (this.failure !== undefined) {
      const waiters = this.waiters;
      this.waiters = [];
      for (const waiter of waiters) waiter.reject(this.failure);
      return;
    }
    if (this.buffer.length === 0 && !this.ended) return;
    const waiters = this.waiters;
    this.waiters = [];
    for (const waiter of waiters) waiter.resolve();
  }

  /**
   * Wake once more bytes may be available.
   *
   * @returns {Promise<void>}
   */
  wait() {
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  /**
   * Read exactly n bytes.
   *
   * @param {number} n
   * @returns {Promise<Buffer>}
   */
  async readBytes(n) {
    while (this.buffer.length < n) {
      if (this.failure !== undefined) throw this.failure;
      if (this.ended) throw new TunnelError('连接在握手完成前关闭。', 'closed');
      await this.wait();
    }
    const out = this.buffer.subarray(0, n);
    this.buffer = this.buffer.subarray(n);
    return out;
  }

  /**
   * Read and decrypt one handshake frame.
   *
   * @param {Buffer} key
   * @param {number} expectedCounter
   * @returns {Promise<Buffer>}
   */
  async readFrame(key, expectedCounter) {
    const header = await this.readBytes(8);
    const length = header.readUInt32BE(0);
    const counter = header.readUInt32BE(4);
    if (length > MAX_FRAME_BYTES) throw new TunnelError('握手帧过大。', 'bad-frame');
    if (counter !== (expectedCounter >>> 0)) throw new TunnelError('握手帧序号无效。', 'bad-frame');
    const rest = await this.readBytes(length + TAG_BYTES);
    return decryptFrame(key, counter, header, rest.subarray(0, length), rest.subarray(length));
  }

  /**
   * Stop reading and return every byte not consumed by the handshake.
   *
   * @returns {Buffer}
   */
  detach() {
    this.socket.removeListener('data', this.onData);
    this.socket.removeListener('error', this.onError);
    this.socket.removeListener('end', this.onEnd);
    this.socket.removeListener('close', this.onClose);
    const rest = this.buffer;
    this.buffer = Buffer.alloc(0);
    return rest;
  }
}

/**
 * Encrypted duplex channel after the handshake. Supports the same surface the
 * rest of this module uses on plain sockets: `write`, `end`, `pipe`, `pause`,
 * `resume`, `unshift`, `destroy`, `on('data'|'error'|'close'|'end')`.
 */
class SecureChannel extends Duplex {
  /**
   * @param {import('node:net').Socket} socket
   * @param {{
   *   sendKey: Buffer, recvKey: Buffer, sendCounter: number, recvCounter: number,
   *   leftover?: Buffer,
   * }} options
   */
  constructor(socket, options) {
    super();
    // A channel is a socket-like transport: an unhandled 'error' event would
    // otherwise crash the Host process when a peer resets mid-request. Consumers
    // may still attach their own listeners; they receive the same error.
    this.on('error', () => {});
    this.socket = socket;
    this.sendKey = options.sendKey;
    this.recvKey = options.recvKey;
    this.sendCounter = options.sendCounter >>> 0;
    this.recvCounter = options.recvCounter >>> 0;
    this.buffer = Buffer.alloc(0);
    this.onRawData = (chunk) => {
      if (this.destroyed) return;
      this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
      this.pump();
    };
    this.onRawError = (error) => {
      this.destroy(error instanceof Error ? error : new Error(String(error)));
    };
    this.onRawClose = () => {
      if (!this.destroyed) this.destroy();
    };
    socket.on('data', this.onRawData);
    socket.on('error', this.onRawError);
    socket.on('close', this.onRawClose);
    if (options.leftover !== undefined && options.leftover.length > 0) {
      this.onRawData(options.leftover);
    }
  }

  pump() {
    while (!this.destroyed) {
      if (this.buffer.length < 8) return;
      const length = this.buffer.readUInt32BE(0);
      const counter = this.buffer.readUInt32BE(4);
      if (length > MAX_FRAME_BYTES) {
        this.destroy(new TunnelError('加密帧过大。', 'bad-frame'));
        return;
      }
      const total = 8 + length + TAG_BYTES;
      if (this.buffer.length < total) return;
      const header = this.buffer.subarray(0, 8);
      const body = this.buffer.subarray(8, 8 + length);
      const tag = this.buffer.subarray(8 + length, total);
      this.buffer = this.buffer.subarray(total);
      if (counter !== this.recvCounter) {
        this.destroy(new TunnelError('加密帧序号无效。', 'bad-frame'));
        return;
      }
      let plain;
      try {
        plain = decryptFrame(this.recvKey, counter, header, body, tag);
      } catch {
        this.destroy(new TunnelError('加密数据校验失败（设备密钥不匹配或已撤销配对）。', 'auth-failed'));
        return;
      }
      this.recvCounter = (this.recvCounter + 1) >>> 0;
      if (length === 0) {
        this.push(null);
        return;
      }
      if (!this.push(plain)) this.socket.pause();
    }
  }

  _read() {
    if (typeof this.socket.isPaused === 'function' && this.socket.isPaused()) this.socket.resume();
  }

  _write(chunk, encoding, callback) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    if (data.length === 0) {
      callback();
      return;
    }
    let offset = 0;
    const next = () => {
      if (this.destroyed) {
        callback(new Error('channel closed'));
        return;
      }
      if (offset >= data.length) {
        callback();
        return;
      }
      const end = Math.min(offset + MAX_FRAME_BYTES, data.length);
      const frame = encryptFrame(this.sendKey, this.sendCounter, data.subarray(offset, end));
      this.sendCounter = (this.sendCounter + 1) >>> 0;
      offset = end;
      this.socket.write(frame, (error) => {
        if (error) callback(error);
        else next();
      });
    };
    next();
  }

  _final(callback) {
    if (this.destroyed) {
      callback();
      return;
    }
    const frame = encryptFrame(this.sendKey, this.sendCounter, Buffer.alloc(0));
    this.sendCounter = (this.sendCounter + 1) >>> 0;
    this.socket.write(frame, (error) => {
      try {
        this.socket.end();
      } catch {
        // already closed
      }
      callback(error);
    });
  }

  _destroy(error, callback) {
    this.buffer = Buffer.alloc(0);
    try {
      this.socket.destroy();
    } catch {
      // already closed
    }
    callback(error);
  }
}

/**
 * Create the encrypted listener.
 *
 * `lookupPsk(identity)` must return `{ psk: Buffer|Uint8Array, identity }` or a
 * falsy value. `onConnection(channel, identity)` runs only for authenticated
 * handshakes; its first argument is the duplex channel.
 *
 * @param {{
 *   lookupPsk: (identity: string) => ({ psk: Uint8Array, identity?: string } | null | undefined),
 *   onConnection: (channel: Duplex, identity: string) => void,
 *   log?: (message: string) => void,
 * }} options
 * @returns {import('node:net').Server}
 */
export function createPskServer(options) {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('createPskServer requires { lookupPsk, onConnection }');
  }
  const { lookupPsk, onConnection, log } = options;
  if (typeof lookupPsk !== 'function') throw new TypeError('lookupPsk must be a function');
  if (typeof onConnection !== 'function') throw new TypeError('onConnection must be a function');

  return net.createServer({ noDelay: true }, (socket) => {
    socket.on('error', () => {});
    const timer = setTimeout(() => socket.destroy(), HANDSHAKE_TIMEOUT_MS);
    timer.unref?.();
    const reader = new HandshakeReader(socket);
    void (async () => {
      try {
        const prefix = await reader.readBytes(9);
        if (!prefix.subarray(0, 8).equals(CHANNEL_MAGIC)) {
          throw new TunnelError('协议头不匹配。', 'bad-magic');
        }
        const identityLength = prefix[8];
        if (identityLength === 0 || identityLength > MAX_IDENTITY_BYTES) {
          throw new TunnelError('设备标识长度无效。', 'bad-identity');
        }
        const identity = (await reader.readBytes(identityLength)).toString('utf8');
        const clientNonce = await reader.readBytes(NONCE_BYTES);

        let entry;
        try {
          entry = lookupPsk(identity);
        } catch {
          entry = null;
        }
        if (entry === null || entry === undefined) {
          log?.('control handshake rejected (unknown identity)');
          socket.destroy();
          return;
        }
        const psk = Buffer.from(entry.psk ?? []);
        if (psk.length !== 32) {
          socket.destroy();
          return;
        }

        const serverNonce = randomBytes(NONCE_BYTES);
        socket.write(Buffer.concat([CHANNEL_MAGIC, serverNonce]));
        const keys = deriveKeys(psk, clientNonce, serverNonce);

        const auth = await reader.readFrame(keys.c2s, 0);
        let authMessage;
        try {
          authMessage = JSON.parse(auth.toString('utf8'));
        } catch {
          throw new TunnelError('认证帧无效。', 'bad-auth');
        }
        if (authMessage === null || typeof authMessage !== 'object' || authMessage.type !== 'auth') {
          throw new TunnelError('认证帧无效。', 'bad-auth');
        }
        socket.write(encryptFrame(keys.s2c, 0, AUTH_OK_PAYLOAD));

        clearTimeout(timer);
        const leftover = reader.detach();
        const channel = new SecureChannel(socket, {
          sendKey: keys.s2c,
          recvKey: keys.c2s,
          sendCounter: 1,
          recvCounter: 1,
          leftover,
        });
        try {
          onConnection(channel, identity);
        } catch (error) {
          log?.(`control connection handler failed: ${safeErrorText(error)}`);
          channel.destroy();
        }
      } catch (error) {
        clearTimeout(timer);
        log?.(`control handshake rejected (${error?.code ?? 'error'})`);
        socket.destroy();
      }
    })();
  });
}

/**
 * Open one encrypted channel to a peer.
 *
 * @param {{
 *   host: string,
 *   port: number,
 *   psk: string | Uint8Array,
 *   identity: string,
 *   timeoutMs?: number,
 * }} options
 * @returns {Promise<Duplex>}
 */
export function connectPsk(options) {
  const { host, port, psk, identity } = options ?? {};
  if (typeof host !== 'string' || host === '') {
    return Promise.reject(new TunnelError('缺少目标主机地址。', 'bad-target'));
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    return Promise.reject(new TunnelError('目标端口无效。', 'bad-target'));
  }
  if (typeof identity !== 'string' || identity === '') {
    return Promise.reject(new TunnelError('缺少本机设备标识。', 'bad-identity'));
  }
  const identityBytes = Buffer.from(identity, 'utf8');
  if (identityBytes.length === 0 || identityBytes.length > MAX_IDENTITY_BYTES) {
    return Promise.reject(new TunnelError('本机设备标识无效。', 'bad-identity'));
  }
  let key;
  try {
    key = typeof psk === 'string' ? Buffer.from(psk, 'base64url') : Buffer.from(psk ?? []);
  } catch {
    return Promise.reject(new TunnelError('设备密钥无效。', 'bad-psk'));
  }
  if (key.length !== 32) {
    return Promise.reject(new TunnelError('设备密钥无效。', 'bad-psk'));
  }

  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : CONNECT_TIMEOUT_MS;

  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let timer;

    const finish = (outcome, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener('error', onOuterError);
      socket.removeListener('close', onOuterClose);
      if (outcome === 'ok') {
        resolvePromise(value);
      } else {
        socket.destroy();
        rejectPromise(value);
      }
    };

    const socket = net.connect({ host, port, noDelay: true });
    const onOuterError = (error) => {
      finish(
        'error',
        new TunnelError(
          `无法与 ${host}:${port} 建立加密连接（${error?.code ?? 'unknown'}）。`,
          'connect-failed',
          error,
        ),
      );
    };
    const onOuterClose = () => {
      finish('error', new TunnelError(`与 ${host}:${port} 的连接在加密握手完成前关闭。`, 'connect-closed'));
    };
    socket.once('error', onOuterError);
    socket.once('close', onOuterClose);

    timer = setTimeout(() => {
      finish('error', new TunnelError(`连接 ${host}:${port} 超时，请确认局域网/VPN 互通。`, 'connect-timeout'));
    }, timeoutMs);
    timer.unref?.();

    socket.once('connect', () => {
      void (async () => {
        const reader = new HandshakeReader(socket);
        try {
          const clientNonce = randomBytes(NONCE_BYTES);
          const prefix = Buffer.allocUnsafe(9);
          prefix[0] = 0x44;
          // CHANNEL_MAGIC is 8 bytes; write it then the identity length.
          CHANNEL_MAGIC.copy(prefix, 0);
          prefix[8] = identityBytes.length;
          socket.write(Buffer.concat([prefix, identityBytes, clientNonce]));

          const serverReply = await reader.readBytes(CHANNEL_MAGIC.length + NONCE_BYTES);
          if (!serverReply.subarray(0, CHANNEL_MAGIC.length).equals(CHANNEL_MAGIC)) {
            throw new TunnelError('主机协议头不匹配。', 'bad-magic');
          }
          const serverNonce = serverReply.subarray(CHANNEL_MAGIC.length);
          const keys = deriveKeys(key, clientNonce, serverNonce);
          socket.write(encryptFrame(keys.c2s, 0, AUTH_PAYLOAD));

          const authOk = await reader.readFrame(keys.s2c, 0);
          let message;
          try {
            message = JSON.parse(authOk.toString('utf8'));
          } catch {
            throw new TunnelError('主机认证响应无效。', 'bad-auth');
          }
          if (message === null || typeof message !== 'object' || message.type !== 'auth-ok') {
            throw new TunnelError('主机认证响应无效。', 'bad-auth');
          }

          const leftover = reader.detach();
          const channel = new SecureChannel(socket, {
            sendKey: keys.c2s,
            recvKey: keys.s2c,
            sendCounter: 1,
            recvCounter: 1,
            leftover,
          });
          finish('ok', channel);
        } catch (error) {
          reader.detach();
          finish(
            'error',
            error instanceof TunnelError
              ? error
              : new TunnelError(`加密握手失败（${error?.code ?? 'error'}）。`, 'handshake-failed', error),
          );
        }
      })();
    });
  });
}

/**
 * Write one JSON line and wait until it is flushed to the socket.
 *
 * @param {import('node:net').Socket} socket
 * @param {unknown} value
 * @returns {Promise<void>}
 */
export function writeJsonLine(socket, value) {
  return new Promise((resolvePromise, rejectPromise) => {
    if (socket.destroyed === true) {
      rejectPromise(new TunnelError('连接已关闭。', 'socket-closed'));
      return;
    }
    let line;
    try {
      line = `${JSON.stringify(value)}\n`;
    } catch (error) {
      rejectPromise(new TunnelError('无法序列化握手消息。', 'bad-message', error));
      return;
    }
    socket.write(line, 'utf8', (error) => {
      if (error) rejectPromise(new TunnelError('发送握手消息失败。', 'write-failed', error));
      else resolvePromise();
    });
  });
}

/**
 * Read one JSON line (≤ maxBytes, newline terminated, bounded by timeout).
 *
 * Any bytes after the newline are pushed back onto the socket so the caller can
 * continue with raw streaming (the `proxy` acknowledgement case).
 *
 * @param {import('node:net').Socket} socket
 * @param {{ timeoutMs?: number, maxBytes?: number }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function readJsonLine(socket, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : HANDSHAKE_TIMEOUT_MS;
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : CONTROL_LINE_MAX_BYTES;

  return readUntil(socket, {
    timeoutMs,
    maxBytes,
    label: '握手消息',
    find(buffer) {
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return undefined;
      return { end: newline + 1, payloadEnd: newline };
    },
  }).then(({ payload }) => {
    let text = payload.toString('utf8').replace(/\r$/, '').trim();
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new TunnelError('握手消息不是有效的 JSON。', 'bad-line');
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new TunnelError('握手消息必须是 JSON 对象。', 'bad-line');
    }
    return value;
  });
}

/**
 * Read an HTTP head (request or response) and push any excess bytes back.
 *
 * @param {import('node:net').Socket} socket
 * @param {{ timeoutMs?: number, maxBytes?: number }} [options]
 * @returns {Promise<{ head: Buffer, text: string }>}
 */
export function readHttpHead(socket, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : HEAD_TIMEOUT_MS;
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : HTTP_HEAD_MAX_BYTES;

  return readUntil(socket, {
    timeoutMs,
    maxBytes,
    label: 'HTTP 头',
    find(buffer) {
      const crlf = buffer.indexOf('\r\n\r\n');
      if (crlf !== -1) return { end: crlf + 4, payloadEnd: crlf + 4 };
      const lf = buffer.indexOf('\n\n');
      if (lf !== -1) return { end: lf + 2, payloadEnd: lf + 2 };
      return undefined;
    },
  }).then(({ payload }) => ({ head: payload, text: payload.toString('latin1') }));
}

/**
 * Shared delimiter-driven reader. Owns the data/error/timeout listeners and
 * unshifts the remainder once a delimiter is found.
 *
 * @param {import('node:net').Socket} socket
 * @param {{
 *   timeoutMs: number,
 *   maxBytes: number,
 *   label: string,
 *   find: (buffer: Buffer) => ({ end: number, payloadEnd: number } | undefined),
 * }} options
 * @returns {Promise<{ payload: Buffer }>}
 */
function readUntil(socket, options) {
  const { timeoutMs, maxBytes, label, find } = options;
  return new Promise((resolvePromise, rejectPromise) => {
    let buffer = Buffer.alloc(0);
    let settled = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      socket.removeListener('end', onEnd);
    };

    const settle = (outcome, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (outcome === 'ok') resolvePromise(value);
      else rejectPromise(value);
    };

    const fail = (message, code) => settle('error', new TunnelError(message, code));

    const onData = (chunk) => {
      if (settled) return;
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      const found = find(buffer);
      if (found === undefined) {
        if (buffer.length > maxBytes) fail(`${label}过大。`, 'too-large');
        return;
      }
      if (found.end > maxBytes) {
        fail(`${label}过大。`, 'too-large');
        return;
      }
      const payload = buffer.subarray(0, found.payloadEnd);
      const rest = buffer.subarray(found.end);
      socket.pause();
      if (rest.length > 0) socket.unshift(rest);
      settle('ok', { payload });
    };

    const onError = (error) => {
      fail(`${label}读取失败（${error?.code ?? 'error'}）。`, 'read-failed');
    };
    const onClose = () => {
      fail(`连接在读取${label}时关闭。`, 'closed');
    };
    const onEnd = () => {
      fail(`连接在读取${label}时结束。`, 'closed');
    };

    timer = setTimeout(() => fail(`等待${label}超时。`, 'timeout'), timeoutMs);
    timer.unref?.();

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
    socket.on('end', onEnd);
    socket.resume();
  });
}

/**
 * Parse a raw HTTP head into its start line and ordered header list.
 *
 * Values are decoded as latin1 so the head round-trips byte-for-byte through
 * `formatHttpHead`.
 *
 * @param {Buffer | string} raw
 * @returns {{ startLine: string, headers: Array<[string, string]> }}
 */
export function parseHttpHead(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString('latin1') : String(raw ?? '');
  const trimmed = text.replace(/\r\n\r\n$/, '').replace(/\n\n$/, '');
  const lines = trimmed.split(/\r?\n/);
  const startLine = (lines.shift() ?? '').trim();
  const headers = [];
  for (const line of lines) {
    if (line === '') continue;
    if ((line.startsWith(' ') || line.startsWith('\t')) && headers.length > 0) {
      headers[headers.length - 1][1] += ` ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (name === '') continue;
    headers.push([name, value]);
  }
  return { startLine, headers };
}

/**
 * Serialize a parsed head back to wire form (CRLF, blank line terminator).
 *
 * @param {{ startLine: string, headers: Array<[string, string]> }} head
 * @returns {string}
 */
export function formatHttpHead(head) {
  const lines = [head.startLine];
  for (const [name, value] of head.headers) lines.push(`${name}: ${value}`);
  return `${lines.join('\r\n')}\r\n\r\n`;
}

/**
 * @param {Array<[string, string]>} headers
 * @param {string} name Lower-case header name.
 * @returns {string | undefined}
 */
function headerValue(headers, name) {
  for (const [key, value] of headers) {
    if (key.toLowerCase() === name) return value;
  }
  return undefined;
}

/**
 * @param {Array<[string, string]>} headers
 * @param {string} name Lower-case header name.
 * @returns {boolean}
 */
function hasHeader(headers, name) {
  return headers.some(([key]) => key.toLowerCase() === name);
}

/**
 * Detect a protocol upgrade (WebSocket) request.
 *
 * @param {Array<[string, string]>} headers
 * @returns {boolean}
 */
export function isUpgradeRequest(headers) {
  const upgrade = headerValue(headers, 'upgrade');
  if (upgrade === undefined || upgrade === '') return false;
  const connection = headerValue(headers, 'connection') ?? '';
  return connection.toLowerCase().split(',').some((token) => token.trim() === 'upgrade');
}

/**
 * Rewrite the request head for the tunneled host web server.
 *
 * - `Host`/`Origin`/`Referer` point at `127.0.0.1:<webPort>`;
 * - `Proxy-Connection` is dropped;
 * - `Connection: close` unless this is an upgrade;
 * - the captured session cookie is merged into `Cookie`.
 *
 * @param {Buffer | string} rawHead
 * @param {{ webPort: number, sessionCookie?: string }} options
 * @returns {{ text: string, upgrade: boolean }}
 */
export function rewriteRequestHead(rawHead, options) {
  const webPort = options?.webPort;
  if (!Number.isInteger(webPort) || webPort < 1 || webPort > 65_535) {
    throw new TunnelError('主机 Web 端口无效。', 'bad-port');
  }
  const upstreamOrigin = `http://127.0.0.1:${webPort}`;
  const { startLine, headers } = parseHttpHead(rawHead);
  const parts = startLine.split(' ');
  if (parts.length < 3) throw new TunnelError('无效的 HTTP 请求头。', 'bad-head');

  // Origin-form target normalization (a browser proxy request may be absolute).
  let target = parts[1];
  if (/^https?:\/\//i.test(target)) {
    try {
      const url = new URL(target);
      target = `${url.pathname}${url.search}`;
    } catch {
      // keep the original target; the host will reject it if malformed
    }
  }

  const upgrade = isUpgradeRequest(headers);
  const sessionCookie = typeof options.sessionCookie === 'string' ? options.sessionCookie.trim() : '';
  const out = [];
  let hostAdded = false;
  let connectionAdded = false;
  let cookieAdded = false;

  for (const [rawName, value] of headers) {
    const name = rawName.toLowerCase();
    if (name === 'proxy-connection') continue;
    if (name === 'host') {
      out.push(['Host', `127.0.0.1:${webPort}`]);
      hostAdded = true;
      continue;
    }
    if (name === 'origin') {
      out.push(['Origin', upstreamOrigin]);
      continue;
    }
    if (name === 'referer') {
      out.push(['Referer', rewriteAbsoluteOrigin(value, `127.0.0.1:${webPort}`)]);
      continue;
    }
    if (name === 'connection') {
      out.push(['Connection', upgrade ? 'Upgrade' : 'close']);
      connectionAdded = true;
      continue;
    }
    if (name === 'cookie') {
      const merged = mergeCookie(value, sessionCookie);
      if (merged !== '') out.push(['Cookie', merged]);
      cookieAdded = true;
      continue;
    }
    out.push([rawName, value]);
  }

  if (!hostAdded) out.unshift(['Host', `127.0.0.1:${webPort}`]);
  if (!connectionAdded) out.push(['Connection', upgrade ? 'Upgrade' : 'close']);
  if (!cookieAdded && sessionCookie !== '') out.push(['Cookie', sessionCookie]);

  return {
    text: formatHttpHead({ startLine: `${parts[0]} ${target} ${parts.slice(2).join(' ')}`, headers: out }),
    upgrade,
  };
}

/**
 * Rewrite the response head: absolute `Location` values that point at the host
 * loopback origin become `http://localhost:<localPort>`.
 *
 * @param {Buffer | string} rawHead
 * @param {{ webPort: number, localPort: number }} options
 * @returns {{ text: string, status: number }}
 */
export function rewriteResponseHead(rawHead, options) {
  const webPort = options?.webPort;
  const localPort = options?.localPort;
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65_535) {
    throw new TunnelError('本地代理端口无效。', 'bad-port');
  }
  const { startLine, headers } = parseHttpHead(rawHead);
  const statusMatch = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(startLine);
  const status = statusMatch ? Number(statusMatch[1]) : 0;
  if (status === 0) throw new TunnelError('无效的 HTTP 响应头。', 'bad-head');

  const out = [];
  for (const [rawName, value] of headers) {
    if (rawName.toLowerCase() === 'location') {
      out.push([rawName, rewriteLocation(value, webPort, localPort)]);
      continue;
    }
    out.push([rawName, value]);
  }
  return { text: formatHttpHead({ startLine, headers: out }), status };
}

/**
 * Point a loopback-origin absolute URL at the new host name/port.
 *
 * @param {string} value
 * @param {number | undefined} webPort
 * @param {number} localPort
 * @returns {string}
 */
function rewriteLocation(value, webPort, localPort) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return value;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return value;
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const loopback = hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
  if (!loopback) return value;
  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);
  if (webPort !== undefined && port !== webPort) return value;
  return `http://localhost:${localPort}${url.pathname}${url.search}${url.hash}`;
}

/**
 * Replace the origin part of a Referer value with the host loopback origin.
 *
 * @param {string} value
 * @param {string} authority e.g. `127.0.0.1:55241`
 * @returns {string}
 */
function rewriteAbsoluteOrigin(value, authority) {
  try {
    const url = new URL(value);
    return `http://${authority}${url.pathname}${url.search}${url.hash}`;
  } catch {
    return value;
  }
}

/**
 * Merge the captured session cookie into an existing Cookie header. A cookie
 * with the same name as the captured one is replaced, not duplicated.
 *
 * @param {string | undefined} existing
 * @param {string} addition e.g. `dsh_session=abc`
 * @returns {string}
 */
export function mergeCookie(existing, addition) {
  const extra = typeof addition === 'string' ? addition.trim() : '';
  const current = typeof existing === 'string' ? existing.trim() : '';
  if (extra === '') return current;
  if (current === '') return extra;
  const name = extra.split('=', 1)[0].trim();
  const parts = current
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part !== '' && part.split('=', 1)[0].trim() !== name);
  parts.push(extra);
  return parts.join('; ');
}

/**
 * Pipe two sockets bidirectionally and tear both down when either side dies.
 *
 * @param {import('node:net').Socket} left
 * @param {import('node:net').Socket} right
 * @returns {() => void} teardown
 */
export function pipeSockets(left, right) {
  const destroyBoth = () => {
    if (!left.destroyed) left.destroy();
    if (!right.destroyed) right.destroy();
  };
  left.on('error', destroyBoth);
  right.on('error', destroyBoth);
  left.on('close', () => {
    if (!right.destroyed) right.destroy();
  });
  right.on('close', () => {
    if (!left.destroyed) left.destroy();
  });
  left.pipe(right);
  right.pipe(left);
  return destroyBoth;
}

/**
 * Open a tunnel and perform one request/response exchange. The socket stays
 * open on success (needed for `proxy`), and is destroyed on failure.
 *
 * @param {{
 *   host: string, port: number, psk: string | Uint8Array, identity: string,
 *   request: Record<string, unknown>,
 *   connectTimeoutMs?: number, readTimeoutMs?: number,
 * }} options
 * @returns {Promise<{ socket: import('node:tls').TLSSocket, reply: Record<string, unknown> }>}
 */
export async function openClientTunnel(options) {
  const socket = await connectPsk({
    host: options.host,
    port: options.port,
    psk: options.psk,
    identity: options.identity,
    timeoutMs: options.connectTimeoutMs,
  });
  try {
    await writeJsonLine(socket, options.request);
    const reply = await readJsonLine(socket, { timeoutMs: options.readTimeoutMs });
    return { socket, reply };
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

/**
 * Host-side driver for the one-line handshake.
 *
 * Handlers receive the parsed message and the authenticated identity:
 * - `hello(message, identity)` → `{ host, webPort }`
 * - `authUrl(message, identity)` → `{ url, webPort }`
 * - `proxy(message, identity)` → `{ webPort }`, followed by `onProxy(socket, target)`
 *
 * `hello`/`authUrl` are one-shot: the socket is ended after the reply.
 *
 * @param {import('node:tls').TLSSocket} socket
 * @param {string} identity
 * @param {{ hello?: Function, authUrl?: Function, proxy?: Function }} handlers
 * @param {{
 *   timeoutMs?: number, maxBytes?: number,
 *   onProxy?: (socket: import('node:tls').TLSSocket, target: unknown) => void,
 *   log?: (message: string) => void,
 * }} [options]
 * @returns {Promise<void>}
 */
export async function serveTunnelConnection(socket, identity, handlers = {}, options = {}) {
  const { timeoutMs = HANDSHAKE_TIMEOUT_MS, maxBytes = CONTROL_LINE_MAX_BYTES, onProxy, log } = options;

  let message;
  try {
    message = await readJsonLine(socket, { timeoutMs, maxBytes });
  } catch (error) {
    log?.(`control handshake rejected: ${safeErrorText(error)}`);
    if (!socket.destroyed) socket.destroy();
    return;
  }

  const op = typeof message.op === 'string' ? message.op : '';

  try {
    if (op === 'hello') {
      if (typeof handlers.hello !== 'function') throw new TunnelError('主机不支持该操作。', 'unsupported-op');
      const result = await handlers.hello(message, identity);
      await writeJsonLine(socket, { ok: true, ...(result ?? {}) });
      socket.end();
      return;
    }
    if (op === 'auth-url') {
      if (typeof handlers.authUrl !== 'function') throw new TunnelError('主机不支持该操作。', 'unsupported-op');
      const result = await handlers.authUrl(message, identity);
      await writeJsonLine(socket, { ok: true, ...(result ?? {}) });
      socket.end();
      return;
    }
    if (op === 'proxy') {
      if (typeof handlers.proxy !== 'function') throw new TunnelError('主机不支持该操作。', 'unsupported-op');
      const target = await handlers.proxy(message, identity);
      await writeJsonLine(socket, { ok: true });
      if (typeof onProxy === 'function') onProxy(socket, target);
      return;
    }
    throw new TunnelError('未知的隧道操作。', 'unknown-op');
  } catch (error) {
    try {
      await writeJsonLine(socket, { ok: false, error: safeErrorText(error) });
    } catch {
      // peer already gone
    }
    socket.end();
    setTimeout(() => {
      if (!socket.destroyed) socket.destroy();
    }, 1_000).unref?.();
  }
}

/**
 * Minimal HTTP error written to a local browser when the tunnel cannot be
 * established. Contains no internal details.
 *
 * @param {import('node:net').Socket} socket
 * @param {number} statusCode
 * @param {string} statusText
 * @param {string} [body]
 * @returns {boolean} whether the response was written
 */
export function writeHttpError(socket, statusCode, statusText, body = '') {
  if (socket.destroyed === true || socket.writable === false) return false;
  const payload = `${body}`;
  const head = [
    `HTTP/1.1 ${statusCode} ${statusText}`,
    'content-type: text/plain; charset=utf-8',
    `content-length: ${Buffer.byteLength(payload)}`,
    'connection: close',
    '',
    payload,
  ].join('\r\n');
  try {
    socket.end(head, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isLoopbackAddress(value) {
  if (typeof value !== 'string') return false;
  const host = value.replace(/^\[|\]$/g, '');
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

/**
 * Exposed for tests and callers that need to inspect a head's status.
 *
 * @param {Buffer | string} rawHead
 * @returns {number}
 */
export function httpStatusOf(rawHead) {
  const { startLine } = parseHttpHead(rawHead);
  const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(startLine);
  return match ? Number(match[1]) : 0;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isNetSocket(value) {
  return value instanceof net.Socket;
}
