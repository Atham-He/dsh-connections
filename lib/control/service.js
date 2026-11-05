/**
 * `ControlService` — Codex-style device control for the `dsh-connections`
 * bundle.
 *
 * Two DSH machines signed in to the same DeepSeek account pair over an
 * out-of-band link (copy/paste) and then talk directly through a TLS-PSK
 * tunnel on the LAN/VPN:
 *
 * - the **host** listens on `0.0.0.0:<port>` with a TLS 1.3 PSK listener and
 *   answers `hello` / `auth-url` / `proxy` control lines;
 * - the **controller** pairs by decoding the link, verifying the account and
 *   calling `hello`; `connect()` obtains the host's authenticated URL, captures
 *   its session cookie through a temporary `proxy` tunnel, then starts a
 *   loopback HTTP rewrite proxy at `127.0.0.1:0` exposed as
 *   `http://localhost:<port>/` (localhost keeps browser cookies isolated from
 *   any local DSH served at 127.0.0.1).
 *
 * All state lives in `connections/control.json`; see `./state.js`.
 * PSKs, pairing links and DSH process tokens never appear in logs or thrown
 * errors.
 *
 * @module dsh-connections/control/service
 */

import { randomUUID } from 'node:crypto';
import net from 'node:net';
import { hostname } from 'node:os';

import {
  DEFAULT_CONTROL_PORT,
  PAIRING_LINK_TTL_MS,
  PENDING_DEVICE_NAME,
  decodePairingLink,
  defaultState,
  encodePairingLink,
  isDeviceId,
  listAddresses,
  loadState,
  newPsk,
  normalizeState,
  sanitizeDeviceName,
  saveState,
} from './state.js';
import {
  HANDSHAKE_TIMEOUT_MS,
  HEAD_TIMEOUT_MS,
  HTTP_HEAD_MAX_BYTES,
  createPskServer,
  openClientTunnel,
  pipeSockets,
  parseHttpHead,
  readHttpHead,
  rewriteRequestHead,
  rewriteResponseHead,
  safeErrorText,
  serveTunnelConnection,
  writeHttpError,
} from './tunnel.js';

/** Loopback proxy concurrency cap (per paired device). */
const MAX_PROXY_CONNECTIONS = 64;

/** Time budget per address during pair/connect probing. */
const PAIR_ATTEMPT_TIMEOUT_MS = 2_500;

/** Debounce for opportunistic `lastSeenAt` persistence. */
const PERSIST_DEBOUNCE_MS = 5_000;

/** Account/profile cache lifetime; the UI polls status every 3s. */
const ACCOUNT_CACHE_MS = 5_000;

/** Closed-loop label for the local proxy listener. */
const PROXY_HOST = '127.0.0.1';

/**
 * Actionable error with a stable code; messages never include secrets.
 */
export class ControlError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'control-error') {
    super(message);
    this.name = 'ControlError';
    this.code = code;
  }
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function asString(value) {
  return typeof value === 'string' ? value : '';
}

/**
 * @param {unknown} value
 * @param {number} max
 * @returns {string}
 */
function clip(value, max) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);
}

/**
 * Seconds east of UTC, as expected by `getProfile`.
 *
 * @returns {number}
 */
function timezoneOffsetSeconds() {
  return -new Date().getTimezoneOffset() * 60;
}

/**
 * @param {URL} url
 * @returns {number}
 */
function portOf(url) {
  if (url.port !== '') return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

/**
 * Close a net/tls server, resolving even when it never listened.
 *
 * @param {import('node:net').Server | undefined} server
 * @returns {Promise<void>}
 */
function closeServer(server) {
  if (server === undefined || server === null) return Promise.resolve();
  return new Promise((resolvePromise) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolvePromise();
    };
    try {
      server.close(() => finish());
    } catch {
      finish();
      return;
    }
    const timer = setTimeout(finish, 2_000);
    timer.unref?.();
  });
}

/**
 * Device-to-device control service for one DSH host.
 */
export class ControlService {
  /**
   * @param {{
   *   home?: string,
   *   hostName?: string,
   *   version?: string,
   *   locale?: string,
   *   webServer?: { getOrigin: () => string },
   *   connection?: { authenticatedUrl: (input: string) => unknown },
   *   account?: object,
   *   log?: (message: string) => void,
   * }} [options]
   */
  constructor(options = {}) {
    const source = options !== null && typeof options === 'object' ? options : {};
    /** @type {string | undefined} */
    this.home = typeof source.home === 'string' && source.home.trim() !== '' ? source.home : undefined;
    this.hostName = sanitizeDeviceName(source.hostName, hostname());
    this.version = asString(source.version);
    this.locale = asString(source.locale) || 'en';
    this.webServer = source.webServer;
    this.connection = source.connection;
    this.account = source.account;
    this.log = typeof source.log === 'function' ? source.log : () => {};

    /** @type {object | undefined} */
    this.state = undefined;
    this.initialized = false;
    this.disposed = false;
    this.initPromise = undefined;

    /** @type {import('node:tls').Server | undefined} */
    this.listener = undefined;
    /** @type {number | undefined} */
    this.listenPort = undefined;
    this.hostError = '';

    /** identity → live TLS/upstream sockets */
    this.hostSockets = new Map();
    /** deviceId → loopback proxy entry */
    this.proxies = new Map();

    this.accountCache = undefined;
    this.notes = [];
    this.dirty = false;
    this.persistTimer = undefined;
  }

  // ---------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------

  /**
   * Load state, ensure this device's identity and restart an enabled listener.
   *
   * @returns {Promise<object>} current status
   */
  async init() {
    if (this.disposed) throw new ControlError('控制服务已释放，无法初始化。', 'disposed');
    if (this.initialized) return this.status();

    let loaded;
    try {
      loaded = await loadState({ home: this.home, name: this.hostName });
    } catch (error) {
      loaded = defaultState({ name: this.hostName });
      this.notes.push('控制状态文件无法读取，已重置本地控制状态。');
      this.log(`control state reset: ${safeErrorText(error)}`);
    }

    this.state = normalizeState(loaded, { name: this.hostName });
    this.state.thisDevice.name = sanitizeDeviceName(this.state.thisDevice.name, this.hostName);
    this.initialized = true;

    try {
      await this.persist();
    } catch (error) {
      this.notes.push('控制状态无法写入磁盘，配对信息可能无法保存。');
      this.log(`control state save failed: ${safeErrorText(error)}`);
    }

    if (this.state.host.enabled) {
      try {
        await this.startListener(this.state.host.port);
      } catch (error) {
        this.hostError = safeErrorText(error);
        this.notes.push(`控制监听未能自动启动：${this.hostError}`);
        this.log(`control listener restart failed: ${this.hostError}`);
      }
    }

    return this.status();
  }

  /**
   * Human-readable/JSON status for the settings page.
   *
   * @returns {Promise<object>}
   */
  async status() {
    await this.ensureInitialized();
    const account = await this.accountInfo();
    const running = this.listener !== undefined && this.listenPort !== undefined;
    const port = running ? this.listenPort : this.state.host.port;

    let addresses;
    try {
      addresses = listAddresses();
    } catch {
      addresses = ['127.0.0.1'];
    }

    const pending = Object.entries(this.state.host.pending)
      .map(([deviceId, record]) => ({
        deviceId,
        name: record.name,
        createdAt: record.createdAt,
      }))
      .sort((left, right) => left.createdAt - right.createdAt);

    const paired = Object.entries(this.state.host.paired)
      .map(([deviceId, record]) => ({
        deviceId,
        name: record.name,
        pairedAt: record.pairedAt,
        lastSeenAt: record.lastSeenAt,
        connected: this.connectionCount(deviceId) > 0,
      }))
      .sort((left, right) => right.lastSeenAt - left.lastSeenAt);

    const peers = Object.values(this.state.peers)
      .map((peer) => this.publicPeer(peer))
      .sort((left, right) => right.lastConnectedAt - left.lastConnectedAt);

    return {
      account,
      thisDevice: { id: this.state.thisDevice.id, name: this.state.thisDevice.name },
      host: {
        enabled: this.state.host.enabled,
        running,
        port,
        addresses,
        pending,
        paired,
      },
      peers,
      notes: this.buildNotes(account, running, port),
    };
  }

  /**
   * Start listening for controllers on `0.0.0.0:<port>`.
   *
   * @param {{ port?: number }} [options]
   * @returns {Promise<object>} status
   */
  async enable(options = {}) {
    await this.ensureInitialized();
    this.assertActive();
    const origin = this.webOrigin();
    void origin;

    let requested;
    if (options.port === undefined || options.port === null) {
      requested = this.state.host.port || DEFAULT_CONTROL_PORT;
    } else {
      requested = Number(options.port);
    }
    if (!Number.isInteger(requested) || requested < 0 || requested > 65_535) {
      throw new ControlError('控制端口必须是 0-65535 之间的整数。', 'bad-port');
    }

    if (this.listener !== undefined && this.listenPort !== undefined) {
      if (requested === 0 || requested === this.listenPort) {
        if (!this.state.host.enabled) {
          this.state.host.enabled = true;
          await this.persist();
        }
        return this.status();
      }
      await this.stopListener();
    }

    const port = await this.startListener(requested);
    this.state.host.enabled = true;
    this.state.host.port = port;
    await this.persist();
    return this.status();
  }

  /**
   * Stop listening but keep existing pairings (so re-enabling restores them).
   *
   * @returns {Promise<object>} status
   */
  async disable() {
    await this.ensureInitialized();
    this.assertActive();
    await this.stopListener();
    this.state.host.enabled = false;
    await this.persist();
    return this.status();
  }

  /**
   * Generate a one-time pairing link (returns the secret exactly once).
   *
   * @returns {Promise<{ link: string, guestDeviceId: string, expiresAt: number }>}
   */
  async createPairingLink() {
    await this.ensureInitialized();
    this.assertActive();
    const account = await this.requireAccount();
    if (this.listener === undefined || this.listenPort === undefined) {
      throw new ControlError('请先开启“允许其他设备控制此电脑”，再生成配对链接。', 'host-disabled');
    }
    const origin = this.webOrigin();
    void portOf(origin);

    const guestDeviceId = randomUUID();
    const psk = newPsk();
    const createdAt = Date.now();

    // A new link invalidates every previous pending link.
    this.state.host.pending = {};
    this.state.host.pending[guestDeviceId] = {
      psk,
      name: PENDING_DEVICE_NAME,
      createdAt,
    };
    await this.persist();

    const link = encodePairingLink({
      accountId: account.id,
      host: {
        id: this.state.thisDevice.id,
        name: this.state.thisDevice.name,
        addresses: listAddresses(),
        port: this.listenPort,
      },
      guest: { id: guestDeviceId, psk },
      createdAt,
    });

    this.log('control pairing link generated');
    return { link, guestDeviceId, expiresAt: createdAt + PAIRING_LINK_TTL_MS };
  }

  /**
   * Controller: decode a link, verify the account and pair with the host.
   *
   * @param {{ link?: string }} [options]
   * @returns {Promise<{ peer: object }>}
   */
  async pair(options = {}) {
    await this.ensureInitialized();
    this.assertActive();
    let payload;
    try {
      payload = decodePairingLink(options.link);
    } catch (error) {
      throw new ControlError(safeErrorText(error), 'bad-link');
    }

    const account = await this.requireAccount();
    if (payload.accountId !== account.id) {
      throw new ControlError(
        '配对链接属于另一个 DeepSeek 账号（account mismatch），请使用同一账号生成的新链接。',
        'account-mismatch',
      );
    }
    if (payload.host.id === this.state.thisDevice.id) {
      throw new ControlError('不能与当前这台设备自身配对。', 'self-pair');
    }

    const attempt = await this.probe(payload.host.addresses, payload.host.port, payload.guest.psk, {
      op: 'hello',
      name: this.state.thisDevice.name,
      accountId: account.id,
    }, '配对', payload.guest.id);
    const { socket, reply } = attempt;
    try {
      if (reply.ok !== true) {
        throw new ControlError(`主机拒绝了配对：${safeErrorText(reply.error ?? 'unknown error')}`, 'pair-rejected');
      }
      const host = reply.host;
      if (host === null || typeof host !== 'object' || !isDeviceId(host.id)) {
        throw new ControlError('主机返回的配对响应无效，请确认两台设备的 DSH 版本一致。', 'bad-reply');
      }
      if (host.id !== payload.host.id) {
        throw new ControlError('主机身份与配对链接不一致，已中止配对。', 'host-mismatch');
      }
      if (asString(host.accountId) !== account.id) {
        throw new ControlError('主机当前登录的账号与配对链接不一致（account mismatch）。', 'account-mismatch');
      }
      const webPort = Number(reply.webPort);
      if (!Number.isInteger(webPort) || webPort < 1 || webPort > 65_535) {
        throw new ControlError('主机未返回有效的 Web 端口，请确认 DSH 版本一致。', 'bad-reply');
      }

      const now = Date.now();
      const existing = this.state.peers[payload.host.id];
      const peer = {
        deviceId: payload.host.id,
        name: sanitizeDeviceName(host.name ?? payload.host.name, payload.host.name),
        addresses: this.mergeAddresses(existing?.addresses, payload.host.addresses),
        port: payload.host.port,
        psk: payload.guest.psk,
        guestId: payload.guest.id,
        accountId: payload.accountId,
        webPort,
        pairedAt: existing?.pairedAt ?? now,
        lastConnectedAt: existing?.lastConnectedAt ?? 0,
      };
      this.state.peers[peer.deviceId] = peer;
      await this.persist();
      this.log(`control paired with ${peer.deviceId}`);
      return { peer: this.publicPeer(peer) };
    } finally {
      socket.destroy();
    }
  }

  /**
   * Controller: authenticate against the peer, then serve its Web UI through a
   * loopback rewrite proxy.
   *
   * @param {{ deviceId?: string }} [options]
   * @returns {Promise<{ deviceId: string, url: string, localPort: number, webPort: number }>}
   */
  async connect(options = {}) {
    await this.ensureInitialized();
    this.assertActive();
    const deviceId = this.requireDeviceId(options.deviceId);
    const peer = this.state.peers[deviceId];
    if (peer === undefined) {
      throw new ControlError('未找到该设备，请先配对。', 'unknown-peer');
    }
    const account = await this.requireAccount();
    if (peer.accountId !== '' && peer.accountId !== account.id) {
      throw new ControlError(
        '该设备绑定的是另一个 DeepSeek 账号（account mismatch），请移除后重新配对。',
        'account-mismatch',
      );
    }
    if (!Number.isInteger(peer.webPort) || peer.webPort < 1) {
      throw new ControlError('该设备缺少 Web 端口信息，请移除后重新配对。', 'bad-peer');
    }

    // A reconnect always starts from a clean proxy.
    await this.stopProxy(deviceId);

    const auth = await this.probe(peer.addresses, peer.port, peer.psk, { op: 'auth-url' }, '连接', this.peerIdentity(peer));
    let webPort;
    let sessionCookie;
    try {
      if (auth.reply.ok !== true) {
        throw new ControlError(`主机拒绝了连接：${safeErrorText(auth.reply.error ?? 'unknown error')}`, 'connect-rejected');
      }
      const authUrl = asString(auth.reply.url);
      let parsed;
      try {
        parsed = new URL(authUrl);
      } catch {
        throw new ControlError('主机返回的登录地址无效，请重试。', 'bad-reply');
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new ControlError('主机返回的登录地址协议不受支持。', 'bad-reply');
      }
      const reportedPort = Number(auth.reply.webPort);
      webPort = Number.isInteger(reportedPort) && reportedPort > 0 && reportedPort <= 65_535
        ? reportedPort
        : portOf(parsed);
      sessionCookie = await this.captureSessionCookie(peer, authUrl, webPort);
    } finally {
      auth.socket.destroy();
    }

    let entry;
    try {
      entry = await this.startProxy(peer, { webPort, sessionCookie });
    } catch (error) {
      throw new ControlError(`无法启动本地代理：${safeErrorText(error)}`, 'proxy-failed');
    }

    peer.webPort = webPort;
    peer.lastConnectedAt = Date.now();
    await this.persist();

    return {
      deviceId,
      url: `http://localhost:${entry.port}/`,
      localPort: entry.port,
      webPort,
    };
  }

  /**
   * Controller: close the loopback proxy for one device.
   *
   * @param {{ deviceId?: string }} [options]
   * @returns {Promise<{ deviceId: string, disconnected: boolean }>}
   */
  async disconnect(options = {}) {
    await this.ensureInitialized();
    this.assertActive();
    const deviceId = this.requireDeviceId(options.deviceId);
    const closed = await this.stopProxy(deviceId);
    return { deviceId, disconnected: closed };
  }

  /**
   * Remove a pairing: `side: 'guest'` revokes a controller from this host,
   * `side: 'peer'` forgets a remote host on this controller.
   *
   * @param {{ deviceId?: string, side?: string }} [options]
   * @returns {Promise<object>} status
   */
  async unpair(options = {}) {
    await this.ensureInitialized();
    this.assertActive();
    const deviceId = this.requireDeviceId(options.deviceId);
    const side = options.side;

    if (side === 'guest') {
      const known = this.state.host.pending[deviceId] !== undefined ||
        this.state.host.paired[deviceId] !== undefined;
      if (!known) throw new ControlError('未找到该已配对的设备。', 'unknown-device');
      delete this.state.host.pending[deviceId];
      delete this.state.host.paired[deviceId];
      this.destroyHostSockets(deviceId);
      await this.persist();
      this.log(`control device revoked: ${deviceId}`);
      return this.status();
    }

    if (side === 'peer') {
      if (this.state.peers[deviceId] === undefined) {
        throw new ControlError('未找到该已配对的远程设备。', 'unknown-device');
      }
      await this.stopProxy(deviceId);
      delete this.state.peers[deviceId];
      await this.persist();
      this.log(`control peer removed: ${deviceId}`);
      return this.status();
    }

    throw new ControlError("side 必须是 'guest' 或 'peer'。", 'bad-side');
  }

  /**
   * Stop everything. Idempotent; flushes pending state when possible.
   *
   * @returns {Promise<{ disposed: boolean }>}
   */
  async dispose() {
    if (this.disposed) return { disposed: true };
    this.disposed = true;

    if (this.persistTimer !== undefined) {
      clearTimeout(this.persistTimer);
      this.persistTimer = undefined;
    }

    await this.stopListener();
    for (const deviceId of [...this.proxies.keys()]) {
      await this.stopProxy(deviceId);
    }
    for (const deviceId of [...this.hostSockets.keys()]) {
      this.destroyHostSockets(deviceId);
    }
    this.hostSockets.clear();

    if (this.dirty && this.state !== undefined) {
      try {
        await this.persist();
      } catch (error) {
        this.log(`control state flush failed: ${safeErrorText(error)}`);
      }
    }
    return { disposed: true };
  }

  // ---------------------------------------------------------------------
  // Host (TLS-PSK listener)
  // ---------------------------------------------------------------------

  /**
   * @param {number} port
   * @returns {Promise<number>} the bound port
   */
  async startListener(port) {
    await this.stopListener();
    const server = createPskListener(this);

    await new Promise((resolvePromise, rejectPromise) => {
      const onError = (error) => {
        cleanup();
        rejectPromise(new ControlError(
          `无法在 0.0.0.0:${port} 启动控制监听（${error?.code ?? 'unknown'}）。请更换端口或关闭占用该端口的程序。`,
          'listen-failed',
        ));
      };
      const onListening = () => {
        cleanup();
        resolvePromise();
      };
      const cleanup = () => {
        server.removeListener('error', onError);
        server.removeListener('listening', onListening);
      };
      server.once('error', onError);
      server.once('listening', onListening);
      try {
        server.listen({ host: '0.0.0.0', port, exclusive: false });
      } catch (error) {
        onError(error);
      }
    });

    server.on('error', (error) => {
      this.hostError = `控制监听错误（${error?.code ?? 'unknown'}）。`;
      this.log(`control listener error: ${safeErrorText(error)}`);
    });

    const address = server.address();
    const boundPort = address !== null && typeof address === 'object' ? address.port : port;
    this.listener = server;
    this.listenPort = boundPort;
    this.hostError = '';
    this.log(`control listener on 0.0.0.0:${boundPort}`);
    return boundPort;
  }

  /**
   * @returns {Promise<void>}
   */
  async stopListener() {
    const server = this.listener;
    this.listener = undefined;
    this.listenPort = undefined;
    for (const identity of [...this.hostSockets.keys()]) {
      this.destroyHostSockets(identity);
    }
    this.hostSockets.clear();
    await closeServer(server);
  }

  /**
   * Resolve a PSK for an authenticated identity. Unknown identities get null,
   * so they never reach `secureConnection`.
   *
   * @param {string} identity
   * @returns {{ psk: Buffer, identity: string } | null}
   */
  lookupPsk(identity) {
    if (typeof identity !== 'string' || identity === '' || this.state === undefined) return null;
    const record = this.state.host.paired[identity] ?? this.state.host.pending[identity];
    if (record === undefined) return null;
    try {
      const psk = Buffer.from(record.psk, 'base64url');
      if (psk.length !== 32) return null;
      return { psk, identity };
    } catch {
      return null;
    }
  }

  /**
   * @param {import('node:tls').TLSSocket} socket
   * @param {string} identity
   */
  handleHostConnection(socket, identity) {
    if (this.disposed) {
      socket.destroy();
      return;
    }
    this.trackHostSocket(identity, socket);
    void this.serveHostSocket(socket, identity);
  }

  /**
   * @param {import('node:tls').TLSSocket} socket
   * @param {string} identity
   * @returns {Promise<void>}
   */
  async serveHostSocket(socket, identity) {
    try {
      await this.markSeen(identity);
      await serveTunnelConnection(socket, identity, {
        hello: (message) => this.hostHello(identity, message),
        authUrl: () => this.hostAuthUrl(identity),
        proxy: () => this.hostProxyTarget(identity),
      }, {
        timeoutMs: HANDSHAKE_TIMEOUT_MS,
        maxBytes: 8_192,
        onProxy: (tunnel, target) => this.pipeToHostWeb(tunnel, identity, target),
        log: (message) => this.log(message),
      });
    } catch (error) {
      this.log(`control connection failed: ${safeErrorText(error)}`);
      socket.destroy();
    }
  }

  /**
   * Move a pending device to paired and refresh `lastSeenAt`.
   *
   * @param {string} identity
   * @returns {Promise<void>}
   */
  async markSeen(identity) {
    const host = this.state.host;
    const pending = host.pending[identity];
    const now = Date.now();
    if (pending !== undefined) {
      delete host.pending[identity];
      host.paired[identity] = {
        psk: pending.psk,
        name: pending.name === PENDING_DEVICE_NAME ? '已配对设备' : pending.name,
        accountId: '',
        pairedAt: now,
        lastSeenAt: now,
      };
      this.persistSoon();
      return;
    }
    if (host.paired[identity] !== undefined) {
      host.paired[identity].lastSeenAt = now;
      this.persistSoon();
    }
  }

  /**
   * @param {string} identity
   * @param {Record<string, unknown>} message
   * @returns {Promise<{ host: object, webPort: number }>}
   */
  async hostHello(identity, message) {
    if (this.state.host.paired[identity] === undefined) {
      throw new ControlError('该设备未完成配对，请先在主机生成配对链接。', 'not-paired');
    }
    const account = await this.accountInfo(true);
    if (!account.signedIn || account.id === '') {
      throw new ControlError('主机未登录 DeepSeek 账号，无法接受远程控制。', 'host-signed-out');
    }
    const declared = asString(message.accountId);
    if (declared !== account.id) {
      throw new ControlError('账号不一致（account mismatch）：控制端与主机必须登录同一个 DeepSeek 账号。', 'account-mismatch');
    }

    const record = this.state.host.paired[identity];
    record.accountId = account.id;
    const name = sanitizeDeviceName(message.name);
    if (name !== '') record.name = name;
    this.persistSoon();

    const origin = this.webOrigin();
    return {
      host: {
        id: this.state.thisDevice.id,
        name: this.state.thisDevice.name,
        accountId: account.id,
      },
      webPort: portOf(origin),
    };
  }

  /**
   * @param {string} identity
   * @returns {Promise<{ url: string, webPort: number }>}
   */
  async hostAuthUrl(identity) {
    this.assertPaired(identity);
    const url = await this.authenticatedUrl();
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new ControlError('无法生成有效的 DSH 登录地址。', 'auth-url-failed');
    }
    if (parsed.protocol !== 'http:') {
      throw new ControlError('仅支持本机 HTTP DSH Web 载体，无法建立控制隧道。', 'unsupported-web-origin');
    }
    return { url, webPort: portOf(parsed) };
  }

  /**
   * @param {string} identity
   * @returns {{ webPort: number }}
   */
  hostProxyTarget(identity) {
    this.assertPaired(identity);
    const origin = this.webOrigin();
    return { webPort: portOf(origin) };
  }

  /**
   * Turn the authenticated tunnel into a raw byte pipe to the host web server.
   *
   * @param {import('node:tls').TLSSocket} tunnel
   * @param {string} identity
   * @param {{ webPort?: number }} target
   */
  pipeToHostWeb(tunnel, identity, target) {
    const webPort = Number(target?.webPort);
    if (!Number.isInteger(webPort) || webPort < 1 || webPort > 65_535) {
      writeHttpError(tunnel, 502, 'Bad Gateway', 'host web port unavailable');
      return;
    }

    const upstream = net.connect({ host: '127.0.0.1', port: webPort });
    this.trackHostSocket(identity, upstream);
    let connected = false;
    upstream.once('connect', () => {
      connected = true;
    });
    upstream.on('error', () => {
      if (!connected) {
        writeHttpError(tunnel, 502, 'Bad Gateway', 'host web server unreachable');
      } else {
        tunnel.destroy();
      }
    });
    tunnel.on('error', () => {
      upstream.destroy();
    });
    pipeSockets(tunnel, upstream);
  }

  /**
   * @param {string} identity
   * @param {import('node:net').Socket} socket
   */
  trackHostSocket(identity, socket) {
    let set = this.hostSockets.get(identity);
    if (set === undefined) {
      set = new Set();
      this.hostSockets.set(identity, set);
    }
    set.add(socket);
    socket.once('close', () => {
      set.delete(socket);
      if (set.size === 0 && this.hostSockets.get(identity) === set) {
        this.hostSockets.delete(identity);
      }
    });
  }

  /**
   * @param {string} identity
   */
  destroyHostSockets(identity) {
    const set = this.hostSockets.get(identity);
    if (set === undefined) return;
    this.hostSockets.delete(identity);
    for (const socket of set) {
      if (!socket.destroyed) socket.destroy();
    }
    set.clear();
  }

  /**
   * @param {string} identity
   * @returns {number}
   */
  connectionCount(identity) {
    const set = this.hostSockets.get(identity);
    return set === undefined ? 0 : set.size;
  }

  /**
   * @param {string} identity
   */
  assertPaired(identity) {
    if (this.state.host.paired[identity] === undefined) {
      throw new ControlError('该设备未完成配对，请先在主机生成配对链接。', 'not-paired');
    }
  }

  // ---------------------------------------------------------------------
  // Controller (loopback HTTP rewrite proxy)
  // ---------------------------------------------------------------------

  /**
   * Read the host's authenticated URL through a temporary tunnel and capture
   * the resulting session cookie (the host answers with 303 + Set-Cookie).
   *
   * @param {object} peer
   * @param {string} authUrl
   * @param {number} webPort
   * @returns {Promise<string>}
   */
  async captureSessionCookie(peer, authUrl, webPort) {
    let parsed;
    try {
      parsed = new URL(authUrl);
    } catch {
      throw new ControlError('主机返回的登录地址无效，请重试。', 'bad-reply');
    }
    const target = `${parsed.pathname}${parsed.search}`;
    const attempt = await this.probe(peer.addresses, peer.port, peer.psk, { op: 'proxy' }, '连接', this.peerIdentity(peer));
    const { socket, reply } = attempt;
    try {
      if (reply.ok !== true) {
        throw new ControlError(`主机拒绝了代理请求：${safeErrorText(reply.error ?? 'unknown error')}`, 'proxy-rejected');
      }
      const request = [
        `GET ${target} HTTP/1.1`,
        `Host: 127.0.0.1:${webPort}`,
        'Accept: */*',
        'Connection: close',
        '',
        '',
      ].join('\r\n');
      socket.write(request, 'latin1');
      const head = await readHttpHead(socket, { timeoutMs: 10_000, maxBytes: HTTP_HEAD_MAX_BYTES });
      const { headers } = parseHttpHead(head.text);
      const cookies = [];
      for (const [name, value] of headers) {
        if (name.toLowerCase() !== 'set-cookie') continue;
        const pair = value.split(';', 1)[0].trim();
        if (pair !== '') cookies.push(pair);
      }
      if (cookies.length === 0) {
        throw new ControlError('无法通过隧道完成 DSH 登录（主机未返回会话 Cookie），请重试。', 'auth-failed');
      }
      return cookies.join('; ');
    } catch (error) {
      socket.destroy();
      if (error instanceof ControlError) throw error;
      throw new ControlError(`无法通过隧道完成 DSH 登录：${safeErrorText(error)}`, 'auth-failed');
    }
  }

  /**
   * @param {object} peer
   * @param {{ webPort: number, sessionCookie: string }} session
   * @returns {Promise<object>} proxy entry
   */
  async startProxy(peer, session) {
    const entry = {
      deviceId: peer.deviceId,
      webPort: session.webPort,
      cookie: session.sessionCookie,
      server: undefined,
      port: 0,
      sockets: new Set(),
      tunnels: new Set(),
      closed: false,
    };

    const server = net.createServer((client) => this.handleProxyClient(entry, client));
    server.on('error', (error) => {
      this.log(`loopback proxy error: ${safeErrorText(error)}`);
    });

    await new Promise((resolvePromise, rejectPromise) => {
      const onError = (error) => {
        cleanup();
        rejectPromise(error);
      };
      const onListening = () => {
        cleanup();
        resolvePromise();
      };
      const cleanup = () => {
        server.removeListener('error', onError);
        server.removeListener('listening', onListening);
      };
      server.once('error', onError);
      server.once('listening', onListening);
      try {
        server.listen({ host: PROXY_HOST, port: 0 });
      } catch (error) {
        onError(error);
      }
    });

    const address = server.address();
    entry.server = server;
    entry.port = address !== null && typeof address === 'object' ? address.port : 0;
    this.proxies.set(peer.deviceId, entry);
    this.log(`control proxy for ${peer.deviceId} on http://localhost:${entry.port}/`);
    return entry;
  }

  /**
   * @param {object} entry
   * @param {import('node:net').Socket} client
   */
  handleProxyClient(entry, client) {
    if (this.disposed || entry.closed) {
      client.destroy();
      return;
    }
    entry.sockets.add(client);
    client.on('error', () => {});
    client.once('close', () => {
      entry.sockets.delete(client);
    });

    while (entry.sockets.size > MAX_PROXY_CONNECTIONS) {
      const oldest = entry.sockets.values().next().value;
      if (oldest === undefined || oldest === client) break;
      entry.sockets.delete(oldest);
      oldest.destroy();
    }

    void this.runProxyClient(entry, client).catch((error) => {
      this.log(`loopback proxy request failed: ${safeErrorText(error)}`);
      const message = error instanceof ControlError
        ? error.message
        : '控制隧道请求失败，请确认另一台设备在线后重试。';
      if (!writeHttpError(client, 502, 'Bad Gateway', message)) client.destroy();
    });
  }

  /**
   * One local browser connection: request head rewrite, tunnel, response head
   * rewrite, then raw piping (which also carries WebSocket upgrades).
   *
   * @param {object} entry
   * @param {import('node:net').Socket} client
   * @returns {Promise<void>}
   */
  async runProxyClient(entry, client) {
    const peer = this.state.peers[entry.deviceId];
    if (peer === undefined) {
      throw new ControlError('该设备已被移除，请关闭此页面。', 'unknown-peer');
    }

    const head = await readHttpHead(client, { timeoutMs: 10_000, maxBytes: HTTP_HEAD_MAX_BYTES });
    if (entry.closed || this.disposed || client.destroyed) {
      client.destroy();
      return;
    }

    let rewritten;
    try {
      rewritten = rewriteRequestHead(head.text, {
        webPort: entry.webPort,
        sessionCookie: entry.cookie,
      });
    } catch {
      writeHttpError(client, 400, 'Bad Request', 'invalid HTTP request');
      return;
    }

    const { socket: tunnel } = await this.openProxyTunnel(entry, peer);
    entry.tunnels.add(tunnel);
    tunnel.once('close', () => entry.tunnels.delete(tunnel));

    const destroyBoth = () => {
      if (!client.destroyed) client.destroy();
      if (!tunnel.destroyed) tunnel.destroy();
    };
    client.on('error', destroyBoth);
    tunnel.on('error', destroyBoth);
    client.once('close', () => {
      if (!tunnel.destroyed) tunnel.destroy();
    });
    tunnel.once('close', () => {
      if (!client.destroyed) client.destroy();
    });

    try {
      tunnel.write(Buffer.from(rewritten.text, 'latin1'));
      // Stream the request body (if any) while the response head is pending; a
      // POST whose body the host waits for would otherwise deadlock.
      client.pipe(tunnel);
      const responseHead = await readHttpHead(tunnel, {
        timeoutMs: HEAD_TIMEOUT_MS,
        maxBytes: HTTP_HEAD_MAX_BYTES,
      });
      const response = rewriteResponseHead(responseHead.text, {
        webPort: entry.webPort,
        localPort: entry.port,
      });
      client.write(Buffer.from(response.text, 'latin1'));
    } catch (error) {
      destroyBoth();
      throw error;
    }

    tunnel.pipe(client);
  }

  /**
   * @param {object} entry
   * @param {object} peer
   * @returns {Promise<{ socket: import('node:tls').TLSSocket }>}
   */
  async openProxyTunnel(entry, peer) {
    const attempt = await this.probe(peer.addresses, peer.port, peer.psk, { op: 'proxy' }, '打开隧道', this.peerIdentity(peer));
    if (attempt.reply.ok !== true) {
      attempt.socket.destroy();
      throw new ControlError(
        `主机拒绝了代理请求：${safeErrorText(attempt.reply.error ?? 'unknown error')}`,
        'proxy-rejected',
      );
    }
    return { socket: attempt.socket };
  }

  /**
   * Try peer addresses in order and return the first tunnel that answers.
   *
   * @param {string[]} addresses
   * @param {number} port
   * @param {string} psk
   * @param {Record<string, unknown>} request
   * @param {string} label
   * @returns {Promise<{ socket: import('node:tls').TLSSocket, reply: Record<string, unknown>, address: string }>}
   */
  async probe(addresses, port, psk, request, label, identity) {
    const candidates = Array.isArray(addresses) && addresses.length > 0 ? addresses : ['127.0.0.1'];
    let lastError = '';
    for (const address of candidates) {
      try {
        const opened = await openClientTunnel({
          host: address,
          port,
          psk,
          identity: identity ?? this.state.thisDevice.id,
          request,
          connectTimeoutMs: PAIR_ATTEMPT_TIMEOUT_MS,
          readTimeoutMs: HANDSHAKE_TIMEOUT_MS,
        });
        return { socket: opened.socket, reply: opened.reply, address };
      } catch (error) {
        lastError = safeErrorText(error);
        if (this.disposed) break;
      }
    }
    throw new ControlError(
      `${label}失败：无法连接 ${candidates.join(', ')}:${port}。` +
      '请确认两台设备在同一局域网/VPN、主机已开启“允许其他设备控制此电脑”，并允许防火墙入站。' +
      (lastError === '' ? '' : `（最后错误：${lastError}）`),
      'unreachable',
    );
  }

  /**
   * @param {string} deviceId
   * @returns {Promise<boolean>} whether a proxy was closed
   */
  async stopProxy(deviceId) {
    const entry = this.proxies.get(deviceId);
    if (entry === undefined) return false;
    this.proxies.delete(deviceId);
    entry.closed = true;

    for (const socket of entry.sockets) {
      if (!socket.destroyed) socket.destroy();
    }
    entry.sockets.clear();
    for (const tunnel of entry.tunnels) {
      if (!tunnel.destroyed) tunnel.destroy();
    }
    entry.tunnels.clear();

    await closeServer(entry.server);
    this.log(`control proxy closed for ${deviceId}`);
    return true;
  }

  // ---------------------------------------------------------------------
  // Shared helpers
  // ---------------------------------------------------------------------

  /**
   * @param {object} peer
   * @returns {object}
   */
  /**
   * Auth identity of a paired controller: the host-generated guest id from the
   * pairing link. Older peer records fall back to this device id.
   *
   * @param {object} peer
   * @returns {string}
   */
  peerIdentity(peer) {
    return typeof peer.guestId === 'string' && peer.guestId !== '' ? peer.guestId : this.state.thisDevice.id;
  }

  publicPeer(peer) {
    const entry = this.proxies.get(peer.deviceId);
    return {
      deviceId: peer.deviceId,
      name: peer.name,
      addresses: [...peer.addresses],
      port: peer.port,
      accountId: peer.accountId,
      connected: entry !== undefined,
      localPort: entry === undefined ? null : entry.port,
      pairedAt: peer.pairedAt,
      lastConnectedAt: peer.lastConnectedAt,
    };
  }

  /**
   * @param {string[] | undefined} existing
   * @param {string[]} incoming
   * @returns {string[]}
   */
  mergeAddresses(existing, incoming) {
    const merged = [];
    const seen = new Set();
    for (const address of [...(Array.isArray(incoming) ? incoming : []), ...(Array.isArray(existing) ? existing : [])]) {
      if (typeof address !== 'string' || address === '' || seen.has(address)) continue;
      if (address !== '127.0.0.1') seen.add(address);
      merged.push(address);
    }
    return merged.length > 0 ? merged : ['127.0.0.1'];
  }

  /**
   * @returns {object}
   */
  async accountInfo(force = false) {
    const now = Date.now();
    if (!force && this.accountCache !== undefined && now - this.accountCache.at < ACCOUNT_CACHE_MS) {
      return { ...this.accountCache.value };
    }

    const info = { signedIn: false, id: '', name: '', contact: '', error: '' };
    if (this.account === undefined || this.account === null) {
      this.accountCache = { at: now, value: { ...info } };
      return { ...info };
    }

    try {
      const raw = await this.account.getState();
      const status = asString(raw?.status);
      info.signedIn = status === 'credential-stored';

      let identity;
      try {
        identity = typeof this.account.getDeviceIdentity === 'function'
          ? await this.account.getDeviceIdentity()
          : undefined;
      } catch (error) {
        info.error = `读取设备身份失败：${safeErrorText(error)}`;
      }
      info.id = clip(identity?.userId, 256);
      if (info.signedIn && info.id === '') {
        info.error = info.error || '无法获取 DeepSeek 账号标识，请重新登录。';
      }

      if (info.signedIn && typeof this.account.getProfile === 'function') {
        const profile = await this.account.getProfile({
          version: this.version,
          locale: this.locale,
          timezoneOffsetSeconds: timezoneOffsetSeconds(),
        });
        if (profile !== null && typeof profile === 'object' && profile.status === 'ready' && profile.value) {
          info.name = sanitizeDeviceName(profile.value.name);
          info.contact = clip(profile.value.contact, 160);
        } else if (profile !== null && typeof profile === 'object' && profile.status === 'failed') {
          info.error = info.error || '账号资料加载失败。';
        }
      }
    } catch (error) {
      info.signedIn = false;
      info.error = `读取 DeepSeek 账号状态失败：${safeErrorText(error)}`;
    }

    this.accountCache = { at: now, value: { ...info } };
    return { ...info };
  }

  /**
   * @returns {Promise<{ signedIn: boolean, id: string, name: string, contact: string, error: string }>}
   */
  async requireAccount() {
    const account = await this.accountInfo(true);
    if (!account.signedIn) {
      throw new ControlError('需要先登录 DeepSeek 账号。两台设备必须登录同一账号才能配对。', 'signed-out');
    }
    if (account.id === '') {
      throw new ControlError('无法获取 DeepSeek 账号标识，请重新登录后再试。', 'no-account-id');
    }
    return account;
  }

  /**
   * @returns {URL}
   */
  webOrigin() {
    if (this.webServer === undefined || this.webServer === null || typeof this.webServer.getOrigin !== 'function') {
      throw new ControlError('当前 DSH 实例不提供 Web 服务信息，无法建立控制隧道。', 'no-web-server');
    }
    let origin;
    try {
      origin = this.webServer.getOrigin();
    } catch (error) {
      throw new ControlError(`无法读取 DSH Web 地址：${safeErrorText(error)}`, 'no-web-server');
    }
    if (typeof origin !== 'string' || origin.trim() === '') {
      throw new ControlError('当前 DSH 实例未报告 Web 地址，无法建立控制隧道。', 'no-web-server');
    }
    let url;
    try {
      url = new URL(origin.trim());
    } catch {
      throw new ControlError('DSH Web 地址无效，无法建立控制隧道。', 'bad-web-origin');
    }
    if (url.protocol !== 'http:') {
      throw new ControlError('仅支持本机 HTTP DSH Web 载体，当前为 ' + url.protocol + '，无法建立控制隧道。', 'unsupported-web-origin');
    }
    return url;
  }

  /**
   * @returns {Promise<string>}
   */
  async authenticatedUrl() {
    if (this.connection === undefined || this.connection === null || typeof this.connection.authenticatedUrl !== 'function') {
      throw new ControlError('当前 DSH 实例不提供 Web 登录能力，无法授权远程浏览器。', 'no-connection');
    }
    const origin = this.webOrigin();
    let url;
    try {
      url = await this.connection.authenticatedUrl(`${origin.protocol}//${origin.host}/`);
    } catch (error) {
      throw new ControlError(`生成 DSH 登录地址失败：${safeErrorText(error)}`, 'auth-url-failed');
    }
    if (typeof url !== 'string' || url.trim() === '') {
      throw new ControlError('无法生成 DSH 登录地址。', 'auth-url-failed');
    }
    return url.trim();
  }

  /**
   * @param {object} account
   * @param {boolean} running
   * @param {number} port
   * @returns {string[]}
   */
  buildNotes(account, running, port) {
    const notes = [];
    for (const note of this.notes) {
      if (typeof note === 'string' && note !== '' && !notes.includes(note)) notes.push(note);
    }
    if (!account.signedIn) {
      notes.push('未登录 DeepSeek 账号：两台设备必须登录同一账号才能配对。');
    }
    if (account.error !== '' && !notes.includes(account.error)) notes.push(account.error);
    if (this.state.host.enabled && !running) {
      notes.push('控制监听未运行，请先关闭再重新开启。');
    }
    try {
      this.webOrigin();
    } catch (error) {
      const message = safeErrorText(error);
      if (!notes.includes(message)) notes.push(message);
    }
    if (running) {
      notes.push(`防火墙提示：若另一台设备无法连接，请允许 TCP ${port} 入站（局域网/VPN 需互通）。`);
    }
    return notes;
  }

  /**
   * @returns {Promise<void>}
   */
  async ensureInitialized() {
    if (this.disposed) throw new ControlError('控制服务已释放。', 'disposed');
    if (this.initialized) return;
    if (this.initPromise === undefined) {
      this.initPromise = this.init().finally(() => {
        this.initPromise = undefined;
      });
    }
    await this.initPromise;
  }

  /**
   * @returns {void}
   */
  assertActive() {
    if (this.disposed) throw new ControlError('控制服务已释放。', 'disposed');
  }

  /**
   * @param {unknown} value
   * @returns {string}
   */
  requireDeviceId(value) {
    if (!isDeviceId(value)) {
      throw new ControlError('设备 ID 无效。', 'bad-device-id');
    }
    return value;
  }

  /**
   * @returns {Promise<object>} normalized state document
   */
  async persist() {
    if (this.state === undefined) throw new ControlError('控制服务尚未初始化。', 'not-initialized');
    this.state = await saveState(this.state, { home: this.home });
    this.dirty = false;
    if (this.persistTimer !== undefined) {
      clearTimeout(this.persistTimer);
      this.persistTimer = undefined;
    }
    return this.state;
  }

  /**
   * Debounced best-effort persistence for high-frequency bookkeeping updates.
   *
   * @returns {void}
   */
  persistSoon() {
    this.dirty = true;
    if (this.persistTimer !== undefined) return;
    this.persistTimer = setTimeout(() => {
      this.persistTimer = undefined;
      if (!this.dirty) return;
      this.persist().catch((error) => {
        this.log(`control state save failed: ${safeErrorText(error)}`);
      });
    }, PERSIST_DEBOUNCE_MS);
    this.persistTimer.unref?.();
  }
}

/**
 * Build the TLS-PSK listener bound to a service instance.
 *
 * Kept outside the class so the validated `(socket, identity)` callback shape
 * is explicit and easy to audit.
 *
 * @param {ControlService} service
 * @returns {import('node:tls').Server}
 */
function createPskListener(service) {
  return createPskServer({
    lookupPsk: (identity) => service.lookupPsk(identity),
    onConnection: (socket, identity) => service.handleHostConnection(socket, identity),
    log: (message) => service.log(message),
  });
}

export default ControlService;
