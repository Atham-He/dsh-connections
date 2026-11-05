window.__ModuleLoader__.load({
  id: '@local/dsh-connections',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const NS = 'dsh-connections'
    const CONTROL_POLL_MS = 3000

    /* ------------------------------------------------------------------ *
     * Dictionaries: English is the fallback source; Chinese mirrors it.    *
     * Every visible string in this page comes from here.                   *
     * ------------------------------------------------------------------ */
    const en = {
      'section.label': 'Connections',

      'tabs.ssh': 'SSH',
      'tabs.this': 'This computer',
      'tabs.other': 'Other devices',
      'tabs.aria': 'Connection sections',

      'common.retry': 'Retry',
      'common.reload': 'Reload',
      'common.copy': 'Copy',
      'common.copied': 'Copied to clipboard.',
      'common.copyError': 'Could not copy. Select the text and copy it manually.',
      'common.never': 'Never',
      'common.unknown': 'Unknown',
      'common.notes': 'Notes',
      'common.busy': 'Working…',
      'common.httpStatus': 'HTTP {status}',
      'common.clear': 'Clear',

      'ssh.heading': 'SSH',
      'ssh.intro':
        'SSH hosts are read from ~/.ssh/config, Codex-style. The agent drives them through tools: run commands, open interactive shells, copy files, forward ports, or start a DeepSeek Harness on the remote machine.',
      'ssh.loading': 'Loading SSH hosts…',
      'ssh.loadError': 'Could not load SSH hosts.',
      'ssh.loadErrorHint': 'Check that the plugin is running, then try again.',
      'ssh.warningsHeading': 'Warnings',
      'ssh.source': 'from {source}',
      'ssh.identity': 'Identity: {path}',
      'ssh.identityDefault': 'Identity: default keys',
      'ssh.test': 'Test',
      'ssh.testAria': 'Test connection to {alias}',
      'ssh.testing': 'Testing…',
      'ssh.testIdle': 'Not tested',
      'ssh.testOk': 'Connected',
      'ssh.testOkMs': 'Connected · {ms} ms',
      'ssh.testFail': 'Failed',
      'ssh.emptyTitle': 'No hosts yet',
      'ssh.emptyBody': 'Add a Host block to ~/.ssh/config, then reload this page:',
      'ssh.emptyExample': 'Host devbox\n  HostName 192.168.1.20\n  User dev',
      'ssh.emptyDirect':
        'Direct user@host[:port] targets also work without a config entry, for example dev@10.0.0.5:2222.',

      'tools.heading': 'Agent tools',
      'tools.intro': 'The agent uses these tools to operate the hosts above.',
      'tools.exec.desc': 'Run one remote command and return its output.',
      'tools.shell.desc': 'Interactive session: open, send input, read output, and close.',
      'tools.copy.desc': 'Upload or download files with SCP.',
      'tools.tunnel.desc': 'Forward a local port to a remote service.',
      'tools.harness.desc':
        'Start DeepSeek Harness on the remote machine through SSH, then open the returned localhost URL in the browser.',

      'control.loading': 'Loading device control status…',
      'control.loadError': 'Could not load device control status.',
      'control.loadErrorHint': 'Check that the plugin is running, then try again.',
      'control.stale': 'Status may be out of date; reconnecting…',
      'control.signedOut': 'Not signed in',
      'control.accountHint': 'Both computers must be signed in to the same DeepSeek account.',

      'this.heading': 'Control this computer',
      'this.signedOutHint': 'Sign in to DeepSeek before allowing other devices to control this computer.',
      'this.allow': 'Allow other devices to control this computer',
      'this.enableError': 'Could not enable device control.',
      'this.disableError': 'Could not disable device control.',
      'this.enabledNotice': 'Device control enabled.',
      'this.disabledNotice': 'Device control disabled. Existing pairings are kept.',
      'this.listenAddress': 'Listen address',
      'this.running': 'Listening',
      'this.notRunning': 'Enabled but the listener is not running.',
      'this.generateLink': 'Generate pairing link',
      'this.linkError': 'Could not generate a pairing link.',
      'this.linkCreated': 'Pairing link generated.',
      'this.linkLabel': 'One-time pairing link',
      'this.linkSecretHint':
        'Treat this link like a one-time password: it lets another device control this computer. Send it through a safe channel; it is shown only here.',
      'this.pendingHeading': 'Waiting for a device',
      'this.pendingWaiting': 'Waiting for the other device to connect…',
      'this.pairedHeading': 'Paired devices',
      'this.noPaired': 'No devices are paired yet.',
      'this.lastSeen': 'Last seen: {time}',
      'this.lastSeenNever': 'Last seen: never',
      'this.remove': 'Remove',
      'this.removeError': 'Could not remove the paired device.',
      'this.removedNotice': 'Paired device removed.',
      'this.warningTitle': 'Security warning',
      'this.warning':
        'A paired device gets full control of this computer, just like someone sitting at it. Only pair devices you trust, and remove them when you are done.',

      'other.heading': 'Control other devices',
      'other.intro':
        'Pair with another DSH machine on the same DeepSeek account to open its full Web UI here through an encrypted tunnel.',
      'other.linkLabel': 'Pairing link',
      'other.linkPlaceholder': 'Paste the pairing link from the other computer',
      'other.linkPrivacy':
        'The link is a one-time secret that contains the tunnel key. It is never stored in the browser.',
      'other.pair': 'Pair',
      'other.pairError': 'Could not pair with the other computer.',
      'other.pairSuccess': 'Paired with the other computer.',
      'other.pairInputRequired': 'Paste a pairing link first.',
      'other.emptyTitle': 'No paired computers yet',
      'other.empty':
        'Both computers must be signed in to the same DeepSeek account. On the other computer, open Settings → Connections → Control this computer, generate a pairing link, and paste it above. The LAN or VPN must be reachable from this computer.',
      'other.peersHeading': 'Paired computers',
      'other.connectAndOpen': 'Connect and open',
      'other.connectError': 'Could not connect to the other computer.',
      'other.connectSuccess': 'Connected. A new tab should open; if it was blocked, use the address below.',
      'other.disconnect': 'Disconnect',
      'other.disconnectError': 'Could not disconnect from the other computer.',
      'other.disconnectedNotice': 'Disconnected.',
      'other.remove': 'Remove',
      'other.removeError': 'Could not remove the paired computer.',
      'other.removedNotice': 'Paired computer removed.',
      'other.lastConnected': 'Last connected: {time}',
      'other.lastConnectedNever': 'Last connected: never',
      'other.connected': 'Connected',
      'other.notConnected': 'Not connected',
      'other.openUrlLabel': 'Open URL',
      'other.popupBlockedHint':
        'If the browser blocked the new tab, copy the URL above and open it manually.',
    }

    const zh = {
      'section.label': '连接',

      'tabs.ssh': 'SSH',
      'tabs.this': '控制此电脑',
      'tabs.other': '控制其他设备',
      'tabs.aria': '连接功能分区',

      'common.retry': '重试',
      'common.reload': '重新加载',
      'common.copy': '复制',
      'common.copied': '已复制到剪贴板。',
      'common.copyError': '复制失败，请手动选择文本复制。',
      'common.never': '从未',
      'common.unknown': '未知',
      'common.notes': '提示',
      'common.busy': '处理中…',
      'common.httpStatus': 'HTTP {status}',
      'common.clear': '清空',

      'ssh.heading': 'SSH',
      'ssh.intro':
        'SSH 主机读取自 ~/.ssh/config（Codex 风格）。智能体通过工具操作这些主机：执行命令、打开交互式会话、传输文件、转发端口，或在远端机器上启动 DeepSeek Harness。',
      'ssh.loading': '正在读取 SSH 主机…',
      'ssh.loadError': '无法读取 SSH 主机。',
      'ssh.loadErrorHint': '请确认插件正在运行，然后重试。',
      'ssh.warningsHeading': '警告',
      'ssh.source': '来源 {source}',
      'ssh.identity': '密钥：{path}',
      'ssh.identityDefault': '密钥：默认密钥',
      'ssh.test': '测试',
      'ssh.testAria': '测试到 {alias} 的连接',
      'ssh.testing': '测试中…',
      'ssh.testIdle': '未测试',
      'ssh.testOk': '已连接',
      'ssh.testOkMs': '已连接 · {ms} 毫秒',
      'ssh.testFail': '失败',
      'ssh.emptyTitle': '还没有主机',
      'ssh.emptyBody': '在 ~/.ssh/config 中添加一个 Host 块，然后重新加载此页面：',
      'ssh.emptyExample': 'Host devbox\n  HostName 192.168.1.20\n  User dev',
      'ssh.emptyDirect': '也可以直接使用 user@host[:port] 目标，无需配置条目，例如 dev@10.0.0.5:2222。',

      'tools.heading': '智能体工具',
      'tools.intro': '智能体使用以下工具操作上述主机。',
      'tools.exec.desc': '在远端执行单条命令并返回输出。',
      'tools.shell.desc': '交互式会话：打开、发送输入、读取输出并关闭。',
      'tools.copy.desc': '通过 SCP 上传或下载文件。',
      'tools.tunnel.desc': '把本地端口转发到远端服务。',
      'tools.harness.desc':
        '通过 SSH 在远端机器上启动 DeepSeek Harness，然后在浏览器中打开返回的 localhost 地址。',

      'control.loading': '正在读取设备控制状态…',
      'control.loadError': '无法读取设备控制状态。',
      'control.loadErrorHint': '请确认插件正在运行，然后重试。',
      'control.stale': '状态可能已过期，正在重新连接…',
      'control.signedOut': '未登录',
      'control.accountHint': '两台电脑都需要登录同一个 DeepSeek 账号。',

      'this.heading': '控制此电脑',
      'this.signedOutHint': '请先登录 DeepSeek，再允许其他设备控制此电脑。',
      'this.allow': '允许其他设备控制此电脑',
      'this.enableError': '无法开启设备控制。',
      'this.disableError': '无法关闭设备控制。',
      'this.enabledNotice': '已开启设备控制。',
      'this.disabledNotice': '已关闭设备控制，已有配对仍然保留。',
      'this.listenAddress': '监听地址',
      'this.running': '监听中',
      'this.notRunning': '已启用，但监听服务未运行。',
      'this.generateLink': '生成配对链接',
      'this.linkError': '无法生成配对链接。',
      'this.linkCreated': '配对链接已生成。',
      'this.linkLabel': '一次性配对链接',
      'this.linkSecretHint':
        '此链接等同于一次性密码：它可以让另一台设备控制此电脑。请通过安全渠道发送，并只在这里显示。',
      'this.pendingHeading': '等待设备连接',
      'this.pendingWaiting': '等待另一台设备连接…',
      'this.pairedHeading': '已配对设备',
      'this.noPaired': '还没有已配对的设备。',
      'this.lastSeen': '最近活跃：{time}',
      'this.lastSeenNever': '最近活跃：从未',
      'this.remove': '移除',
      'this.removeError': '无法移除已配对的设备。',
      'this.removedNotice': '已移除配对设备。',
      'this.warningTitle': '安全警告',
      'this.warning':
        '已配对的设备可以像坐在本机前一样完全控制这台电脑。只配对可信设备，用完后及时移除。',

      'other.heading': '控制其他设备',
      'other.intro':
        '与同一 DeepSeek 账号下的另一台 DSH 机器配对，即可通过加密隧道在这里打开它的完整 Web 界面。',
      'other.linkLabel': '配对链接',
      'other.linkPlaceholder': '粘贴另一台电脑生成的配对链接',
      'other.linkPrivacy': '该链接是一次性密钥，包含隧道密钥，不会保存在浏览器中。',
      'other.pair': '配对',
      'other.pairError': '无法与另一台电脑配对。',
      'other.pairSuccess': '配对成功。',
      'other.pairInputRequired': '请先粘贴配对链接。',
      'other.emptyTitle': '还没有已配对的电脑',
      'other.empty':
        '两台电脑都需要登录同一个 DeepSeek 账号。在另一台电脑上打开 设置 → 连接 → 控制此电脑，生成配对链接后粘贴到上方。本机需要能访问局域网或 VPN。',
      'other.peersHeading': '已配对的电脑',
      'other.connectAndOpen': '连接并打开',
      'other.connectError': '无法连接到另一台电脑。',
      'other.connectSuccess': '已连接。应会打开新标签页；如果被拦截，请使用下面的地址。',
      'other.disconnect': '断开',
      'other.disconnectError': '无法断开与另一台电脑的连接。',
      'other.disconnectedNotice': '已断开连接。',
      'other.remove': '移除',
      'other.removeError': '无法移除已配对的电脑。',
      'other.removedNotice': '已移除已配对的电脑。',
      'other.lastConnected': '最近连接：{time}',
      'other.lastConnectedNever': '最近连接：从未',
      'other.connected': '已连接',
      'other.notConnected': '未连接',
      'other.openUrlLabel': '打开地址',
      'other.popupBlockedHint': '如果浏览器拦截了新标签页，请复制上面的地址手动打开。',
    }

    /* ------------------------------------------------------------------ *
     * Module-scope service handles (assigned by apply; used by the page).   *
     * ------------------------------------------------------------------ */
    let t = function fallbackTranslate(key) {
      return key
    }
    let localeService

    /** Re-render when the active locale changes so body copy follows it. */
    function useLocaleRevision() {
      const pair = React.useState(0)
      const setRevision = pair[1]
      React.useEffect(function () {
        if (!localeService || typeof localeService.subscribe !== 'function') return undefined
        let active = true
        let off
        try {
          off = localeService.subscribe(function () {
            if (active) setRevision(function (revision) { return revision + 1 })
          })
        } catch (error) {
          off = undefined
        }
        return function () {
          active = false
          if (typeof off === 'function') {
            try {
              off()
            } catch (error) {
              /* ignore: unsubscribing must never break teardown */
            }
          }
        }
      }, [])
    }

    /* ------------------------------------------------------------------ *
     * HTTP helpers. GETs reject on non-ok; POST errors carry `detail`.      *
     * ------------------------------------------------------------------ */
    function requestJson(url, options) {
      if (typeof fetch !== 'function') return Promise.reject(new Error('fetch unavailable'))
      return fetch(url, options).then(function (response) {
        if (!response || !response.ok) {
          const error = new Error('request failed')
          if (response && typeof response.status === 'number') error.status = response.status
          throw error
        }
        return response.json()
      })
    }

    function postJson(url, body) {
      if (typeof fetch !== 'function') return Promise.reject(new Error('fetch unavailable'))
      let pending
      try {
        pending = fetch(url, {
          method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(body),
        })
      } catch (error) {
        return Promise.reject(error)
      }
      return pending.then(function (response) {
        if (!response || typeof response.json !== 'function') throw new Error('request failed')
        return response
          .json()
          .catch(function () { return undefined })
          .then(function (payload) {
            if (response.ok) return payload
            const error = new Error('request failed')
            if (typeof response.status === 'number') error.status = response.status
            if (payload && typeof payload.code === 'string') error.code = payload.code
            if (payload && typeof payload.message === 'string' && payload.message !== '') {
              error.detail = payload.message
            }
            throw error
          })
      })
    }

    /* ------------------------------------------------------------------ *
     * Payload normalization (defensive against malformed responses).        *
     * ------------------------------------------------------------------ */
    function toPort(value) {
      const port = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN
      return Number.isInteger(port) && port > 0 && port <= 65535 ? port : undefined
    }

    function stringField(value) {
      return typeof value === 'string' && value !== '' ? value : undefined
    }

    function stringList(value) {
      if (!Array.isArray(value)) return []
      return value.filter(function (item) { return typeof item === 'string' && item !== '' })
    }

    function recordList(value, mapper) {
      if (!Array.isArray(value)) return []
      const out = []
      for (let index = 0; index < value.length; index += 1) {
        const item = value[index]
        if (!item || typeof item !== 'object') continue
        const mapped = mapper(item)
        if (mapped) out.push(mapped)
      }
      return out
    }

    function sanitizeHosts(raw) {
      if (!Array.isArray(raw)) return []
      const hosts = []
      for (let index = 0; index < raw.length; index += 1) {
        const item = raw[index]
        if (!item || typeof item !== 'object') continue
        const alias = stringField(item.alias)
        if (!alias) continue
        hosts.push({
          alias: alias,
          hostName: stringField(item.hostName),
          user: stringField(item.user),
          port: toPort(item.port),
          identityFile: stringField(item.identityFile),
          source: stringField(item.source) || 'ssh-config',
        })
      }
      return hosts
    }

    function sanitizePendingDevice(item) {
      const deviceId = stringField(item.deviceId)
      if (!deviceId) return undefined
      return {
        deviceId: deviceId,
        name: stringField(item.name),
        createdAt: typeof item.createdAt === 'number' ? item.createdAt : undefined,
      }
    }

    function sanitizePairedDevice(item) {
      const deviceId = stringField(item.deviceId)
      if (!deviceId) return undefined
      return {
        deviceId: deviceId,
        name: stringField(item.name),
        pairedAt: typeof item.pairedAt === 'number' ? item.pairedAt : undefined,
        lastSeenAt: typeof item.lastSeenAt === 'number' ? item.lastSeenAt : undefined,
        connected: item.connected === true,
      }
    }

    function sanitizePeer(item) {
      const deviceId = stringField(item.deviceId)
      if (!deviceId) return undefined
      return {
        deviceId: deviceId,
        name: stringField(item.name),
        addresses: stringList(item.addresses),
        port: toPort(item.port),
        accountId: stringField(item.accountId),
        connected: item.connected === true,
        localPort: toPort(item.localPort),
        pairedAt: typeof item.pairedAt === 'number' ? item.pairedAt : undefined,
        lastConnectedAt: typeof item.lastConnectedAt === 'number' ? item.lastConnectedAt : undefined,
      }
    }

    function sanitizeStatus(raw) {
      if (!raw || typeof raw !== 'object') return undefined
      const accountRaw = raw.account && typeof raw.account === 'object' ? raw.account : null
      if (!accountRaw) return undefined
      const hostRaw = raw.host && typeof raw.host === 'object' ? raw.host : {}
      const thisRaw = raw.thisDevice && typeof raw.thisDevice === 'object' ? raw.thisDevice : {}
      return {
        account: {
          signedIn: accountRaw.signedIn === true,
          id: stringField(accountRaw.id),
          name: stringField(accountRaw.name),
          contact: stringField(accountRaw.contact),
          error: stringField(accountRaw.error),
        },
        thisDevice: {
          id: stringField(thisRaw.id),
          name: stringField(thisRaw.name),
        },
        host: {
          enabled: hostRaw.enabled === true,
          running: hostRaw.running === true,
          port: toPort(hostRaw.port),
          addresses: stringList(hostRaw.addresses),
          pending: recordList(hostRaw.pending, sanitizePendingDevice),
          paired: recordList(hostRaw.paired, sanitizePairedDevice),
        },
        peers: recordList(raw.peers, sanitizePeer),
        notes: stringList(raw.notes),
      }
    }

    function loadHosts() {
      return requestJson('/dsh-connections/hosts', {
        method: 'GET',
        headers: { accept: 'application/json' },
        credentials: 'same-origin',
        cache: 'no-store',
      }).then(function (payload) {
        if (!payload || typeof payload !== 'object' || !Array.isArray(payload.hosts)) {
          throw new Error('malformed hosts payload')
        }
        return {
          path: stringField(payload.path),
          hosts: sanitizeHosts(payload.hosts),
          warnings: stringList(payload.warnings),
        }
      })
    }

    function fetchControlStatus() {
      return requestJson('/dsh-connections/control/status', {
        method: 'GET',
        headers: { accept: 'application/json' },
        credentials: 'same-origin',
        cache: 'no-store',
      }).then(function (payload) {
        const sanitized = sanitizeStatus(payload)
        if (!sanitized) throw new Error('malformed control status')
        return sanitized
      })
    }

    function runHostTest(alias) {
      if (typeof fetch !== 'function') return Promise.reject(new Error('fetch unavailable'))
      return fetch('/dsh-connections/test', {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ host: alias }),
      }).then(function (response) {
        if (!response || typeof response.json !== 'function') throw new Error('request failed')
        return response
          .json()
          .catch(function () { return undefined })
          .then(function (payload) {
            if (response.ok && payload && payload.ok === true) {
              return {
                phase: 'ok',
                ms: typeof payload.ms === 'number' ? Math.max(0, Math.round(payload.ms)) : undefined,
              }
            }
            let detail
            if (payload && typeof payload.error === 'string' && payload.error !== '') detail = payload.error
            else if (payload && typeof payload.detail === 'string' && payload.detail !== '') detail = payload.detail
            return { phase: 'fail', detail: detail }
          })
      })
    }

    function hostTarget(host) {
      const name = host.hostName || host.alias
      const base = host.user ? host.user + '@' + name : name
      return host.port && host.port !== 22 ? base + ':' + host.port : base
    }

    function formatTime(value) {
      const ms = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN
      if (!Number.isFinite(ms) || ms <= 0) return t('common.never')
      try {
        return new Date(ms).toLocaleString()
      } catch (error) {
        return String(ms)
      }
    }

    function formatPeerAddress(peer) {
      const addresses = Array.isArray(peer.addresses) ? peer.addresses : []
      if (addresses.length === 0) return t('common.unknown')
      return peer.port ? addresses[0] + ':' + peer.port : addresses[0]
    }

    function copyText(value) {
      const nav = typeof navigator !== 'undefined' ? navigator : undefined
      if (!nav || !nav.clipboard || typeof nav.clipboard.writeText !== 'function') {
        return Promise.resolve(false)
      }
      try {
        return nav.clipboard.writeText(value).then(
          function () { return true },
          function () { return false },
        )
      } catch (error) {
        return Promise.resolve(false)
      }
    }

    /* ------------------------------------------------------------------ *
     * Page styles. Scoped by dsh-connections__, rendered inside the page.   *
     * Colors only from --dsw-alias-* theme tokens.                          *
     * ------------------------------------------------------------------ */
    const MONO = 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace'
    const STYLES = [
      '.dsh-connections__root{display:flex;flex-direction:column;gap:20px;max-width:720px;padding:24px;box-sizing:border-box;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__tabs{display:flex;align-items:center;gap:4px;padding:4px;border-radius:10px;background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l1)}',
      '.dsh-connections__tab{appearance:none;border:1px solid transparent;border-radius:8px;background:transparent;color:var(--dsw-alias-label-secondary);font-family:inherit;font-size:13px;line-height:20px;padding:6px 14px;cursor:pointer;flex:1 1 auto;white-space:nowrap}',
      '.dsh-connections__tab:hover{color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__tab--active{border-color:var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font-weight:600}',
      '.dsh-connections__tab:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:1px}',
      '.dsh-connections__panel{display:flex;flex-direction:column;gap:20px}',
      '.dsh-connections__section{display:flex;flex-direction:column;gap:10px}',
      '.dsh-connections__section+.dsh-connections__section{border-top:1px solid var(--dsw-alias-border-l2);padding-top:20px}',
      '.dsh-connections__sectionHead{display:flex;align-items:center;justify-content:space-between;gap:8px}',
      '.dsh-connections__heading{margin:0;font-size:14px;line-height:22px;font-weight:600;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__body{display:flex;flex-direction:column;gap:10px}',
      '.dsh-connections__intro{margin:0;font-size:13px;line-height:20px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__card{border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);overflow:hidden}',
      '.dsh-connections__row{display:flex;align-items:center;gap:12px;padding:12px 14px;border-top:1px solid var(--dsw-alias-border-l2)}',
      '.dsh-connections__row:first-child{border-top:none}',
      '.dsh-connections__rowMain{display:flex;flex-direction:column;gap:3px;flex:1;min-width:0}',
      '.dsh-connections__alias{font-weight:600;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__target{font-family:' + MONO + ';font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.dsh-connections__meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__chip{border:1px solid var(--dsw-alias-border-l2);border-radius:6px;padding:0 6px;font-size:11px;line-height:18px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2)}',
      '.dsh-connections__identity{font-family:' + MONO + ';font-size:11px;line-height:18px;color:var(--dsw-alias-label-secondary);word-break:break-all}',
      '.dsh-connections__button{appearance:none;border:1px solid var(--dsw-alias-border-l1);border-radius:8px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);font-family:inherit;font-size:12px;line-height:18px;padding:4px 10px;cursor:pointer;flex:none}',
      '.dsh-connections__button:hover:not(:disabled){border-color:var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1)}',
      '.dsh-connections__button:disabled{opacity:.55;cursor:default}',
      '.dsh-connections__button:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:1px}',
      '.dsh-connections__actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}',
      '.dsh-connections__field{display:flex;flex-direction:column;gap:6px}',
      '.dsh-connections__fieldTitle{font-size:12px;line-height:18px;font-weight:600;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__hint{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__loading{padding:4px 0;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__stale{font-size:12px;line-height:18px;color:var(--dsw-alias-state-warn-primary)}',
      '.dsh-connections__accountRow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}',
      '.dsh-connections__accountChip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--dsw-alias-border-l1);border-radius:999px;padding:2px 10px;background:var(--dsw-alias-bg-layer-2);font-size:12px;line-height:18px}',
      '.dsh-connections__accountName{font-weight:600;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__accountContact{color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__switchRow{display:flex;align-items:center;justify-content:space-between;gap:12px}',
      '.dsh-connections__switchLabel{font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__switch{position:relative;width:36px;height:20px;flex:none;border-radius:999px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);padding:0;cursor:pointer;transition:background .15s ease,border-color .15s ease}',
      '.dsh-connections__switch[aria-checked="true"]{background:var(--dsw-alias-brand-primary);border-color:var(--dsw-alias-brand-primary)}',
      '.dsh-connections__switch:disabled{opacity:.5;cursor:default}',
      '.dsh-connections__switch:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}',
      '.dsh-connections__switchKnob{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--dsw-alias-bg-base);transition:transform .15s ease}',
      '.dsh-connections__switch[aria-checked="true"] .dsh-connections__switchKnob{transform:translateX(16px)}',
      '.dsh-connections__codeBox{display:block;width:100%;box-sizing:border-box;margin:0;padding:8px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);font-family:' + MONO + ';font-size:12px;line-height:18px;resize:vertical;min-height:52px;white-space:pre-wrap;overflow-wrap:anywhere}',
      '.dsh-connections__codeBox:focus{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:0}',
      '.dsh-connections__codeBox::placeholder{color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__url{font-family:' + MONO + ';font-size:12px;line-height:18px;color:var(--dsw-alias-label-primary);word-break:break-all}',
      '.dsh-connections__listRow{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 14px;border-top:1px solid var(--dsw-alias-border-l2)}',
      '.dsh-connections__listRow:first-child{border-top:none}',
      '.dsh-connections__listMain{display:flex;flex-direction:column;gap:2px;min-width:0}',
      '.dsh-connections__listTitle{font-weight:600;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__deviceRow{display:flex;flex-direction:column;gap:6px;padding:10px 14px;border-top:1px solid var(--dsw-alias-border-l2)}',
      '.dsh-connections__deviceRow:first-child{border-top:none}',
      '.dsh-connections__deviceHead{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}',
      '.dsh-connections__deviceName{font-weight:600;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__deviceMeta{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__status{display:inline-flex;align-items:center;gap:6px;font-size:12px;line-height:18px;white-space:nowrap}',
      '.dsh-connections__dot{width:7px;height:7px;border-radius:50%;flex:none;background:var(--dsw-alias-state-idle-primary)}',
      '.dsh-connections__dot--testing{background:var(--dsw-alias-brand-primary)}',
      '.dsh-connections__dot--ok{background:var(--dsw-alias-state-success-primary)}',
      '.dsh-connections__dot--fail{background:var(--dsw-alias-state-error-primary)}',
      '.dsh-connections__statusText{color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__statusText--testing{color:var(--dsw-alias-brand-primary)}',
      '.dsh-connections__statusText--ok{color:var(--dsw-alias-state-success-primary)}',
      '.dsh-connections__statusText--fail{color:var(--dsw-alias-state-error-primary)}',
      '.dsh-connections__testCell{display:flex;align-items:center;gap:8px;flex:none}',
      '.dsh-connections__failDetail{font-size:11px;line-height:17px;color:var(--dsw-alias-state-error-primary);overflow-wrap:anywhere}',
      '.dsh-connections__feedback{display:flex;flex-direction:column;gap:2px;font-size:12px;line-height:18px}',
      '.dsh-connections__feedback--error{color:var(--dsw-alias-state-error-primary)}',
      '.dsh-connections__feedback--notice{color:var(--dsw-alias-state-success-primary)}',
      '.dsh-connections__feedbackDetail{font-family:' + MONO + ';font-size:11px;line-height:17px;color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}',
      '.dsh-connections__error{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid var(--dsw-alias-border-l1);border-left:3px solid var(--dsw-alias-state-error-primary);border-radius:8px;background:var(--dsw-alias-bg-layer-1);padding:10px 12px}',
      '.dsh-connections__errorText{display:flex;flex-direction:column;gap:2px;min-width:0}',
      '.dsh-connections__errorTitle{font-weight:600;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__muted{color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__empty{display:flex;flex-direction:column;gap:8px;border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);padding:14px}',
      '.dsh-connections__emptyTitle{font-weight:600;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__pre{margin:0;padding:10px 12px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-2);font-family:' + MONO + ';font-size:12px;line-height:18px;color:var(--dsw-alias-label-primary);white-space:pre-wrap;overflow-wrap:anywhere}',
      '.dsh-connections__warn{display:flex;flex-direction:column;gap:4px;border:1px solid var(--dsw-alias-border-l1);border-left:3px solid var(--dsw-alias-state-warn-primary);border-radius:8px;background:var(--dsw-alias-bg-layer-1);padding:10px 12px}',
      '.dsh-connections__warnTitle{font-weight:600;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__warnList{margin:0;padding-left:18px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-connections__tools{display:flex;flex-direction:column;gap:6px}',
      '.dsh-connections__tool{display:flex;gap:10px;align-items:baseline;font-size:12px;line-height:18px}',
      '.dsh-connections__toolName{flex:none;font-family:' + MONO + ';font-size:12px;line-height:18px;color:var(--dsw-alias-label-primary)}',
      '.dsh-connections__toolDesc{color:var(--dsw-alias-label-secondary)}',
    ].join('')

    /* ------------------------------------------------------------------ *
     * Small class helpers.                                                *
     * ------------------------------------------------------------------ */
    function dotClass(phase) {
      return 'dsh-connections__dot' + (phase === 'idle' ? '' : ' dsh-connections__dot--' + phase)
    }

    function statusTextClass(phase) {
      return 'dsh-connections__statusText' + (phase === 'idle' ? '' : ' dsh-connections__statusText--' + phase)
    }

    /* ------------------------------------------------------------------ *
     * Settings page: SSH, Control this computer, Control other devices.    *
     * ------------------------------------------------------------------ */
    function ConnectionsPage() {
      useLocaleRevision()

      const sshPair = React.useState({ phase: 'loading' })
      const sshView = sshPair[0]
      const setSshView = sshPair[1]

      const sshTokenPair = React.useState(0)
      const sshToken = sshTokenPair[0]
      const setSshToken = sshTokenPair[1]

      const sshTestPair = React.useState({})
      const sshTests = sshTestPair[0]
      const setSshTests = sshTestPair[1]

      const controlPair = React.useState({ phase: 'loading', status: null, errorStatus: undefined, stale: false })
      const control = controlPair[0]
      const setControl = controlPair[1]

      const controlTokenPair = React.useState(0)
      const controlToken = controlTokenPair[0]
      const setControlToken = controlTokenPair[1]

      const busyPair = React.useState({})
      const busy = busyPair[0]
      const setBusy = busyPair[1]

      const linkPair = React.useState(null)
      const link = linkPair[0]
      const setLink = linkPair[1]

      const pairInputPair = React.useState('')
      const pairInput = pairInputPair[0]
      const setPairInput = pairInputPair[1]

      const feedbackPair = React.useState(null)
      const feedback = feedbackPair[0]
      const setFeedback = feedbackPair[1]

      const openedPair = React.useState({})
      const opened = openedPair[0]
      const setOpened = openedPair[1]

      const tabPair = React.useState('ssh')
      const activeTab = tabPair[0]
      const setActiveTab = tabPair[1]

      /* ------------------------------- SSH data ------------------------------ */
      React.useEffect(function () {
        let cancelled = false
        setSshView({ phase: 'loading' })
        loadHosts().then(
          function (payload) {
            if (cancelled) return
            setSshView({ phase: 'ready', path: payload.path, hosts: payload.hosts, warnings: payload.warnings })
          },
          function (error) {
            if (cancelled) return
            setSshView({
              phase: 'error',
              status: error && typeof error.status === 'number' ? error.status : undefined,
            })
          },
        )
        return function () {
          cancelled = true
        }
      }, [sshToken])

      /* --------------------------- Control status poll ----------------------- */
      React.useEffect(function () {
        let disposed = false
        let inFlight = false
        setControl(function (previous) {
          if (previous.phase === 'error') {
            return { phase: 'loading', status: null, errorStatus: undefined, stale: false }
          }
          return previous
        })
        const load = function () {
          if (disposed || inFlight) return
          inFlight = true
          fetchControlStatus()
            .then(
              function (next) {
                if (disposed) return
                setControl({ phase: 'ready', status: next, errorStatus: undefined, stale: false })
              },
              function (error) {
                if (disposed) return
                setControl(function (previous) {
                  if (previous.status) {
                    return { phase: 'ready', status: previous.status, errorStatus: undefined, stale: true }
                  }
                  return {
                    phase: 'error',
                    status: null,
                    errorStatus: error && typeof error.status === 'number' ? error.status : undefined,
                    stale: false,
                  }
                })
              },
            )
            .then(function () {
              inFlight = false
            })
        }
        load()
        const timer = setInterval(load, CONTROL_POLL_MS)
        return function () {
          disposed = true
          clearInterval(timer)
        }
      }, [controlToken])

      /* ------------------------------- Handlers ------------------------------ */
      function setBusyFlag(key, value) {
        setBusy(function (previous) {
          const next = Object.assign({}, previous)
          if (value) next[key] = true
          else delete next[key]
          return next
        })
      }

      function isBusy(key) {
        return busy[key] === true
      }

      function refreshControl() {
        setControlToken(function (token) { return token + 1 })
      }

      function reloadSsh() {
        setSshToken(function (token) { return token + 1 })
      }

      function updateSshTest(key, value) {
        setSshTests(function (previous) {
          const next = Object.assign({}, previous)
          next[key] = value
          return next
        })
      }

      function testConnection(key, alias) {
        updateSshTest(key, { phase: 'testing' })
        runHostTest(alias).then(
          function (result) { updateSshTest(key, result) },
          function () { updateSshTest(key, { phase: 'fail' }) },
        )
      }

      function applyStatus(payload) {
        const sanitized = sanitizeStatus(payload)
        if (!sanitized || !payload || typeof payload.host !== 'object' || payload.host === null) return false
        setControl({ phase: 'ready', status: sanitized, errorStatus: undefined, stale: false })
        return true
      }

      function runAction(key, scope, errorKey, request, onSuccess) {
        setBusyFlag(key, true)
        if (feedback && feedback.scope === scope) setFeedback(null)
        let promise
        try {
          promise = Promise.resolve(request())
        } catch (error) {
          promise = Promise.reject(error)
        }
        promise.then(
          function (payload) {
            setBusyFlag(key, false)
            try {
              onSuccess(payload)
            } catch (error) {
              setFeedback({ scope: scope, kind: 'error', message: t(errorKey) })
            }
          },
          function (error) {
            setBusyFlag(key, false)
            setFeedback({
              scope: scope,
              kind: 'error',
              message: t(errorKey),
              detail: error && typeof error.detail === 'string' ? error.detail : undefined,
            })
          },
        )
      }

      function showNotice(scope, message) {
        setFeedback({ scope: scope, kind: 'notice', message: message })
      }

      function showError(scope, message) {
        setFeedback({ scope: scope, kind: 'error', message: message })
      }

      function copyValue(value, scope) {
        copyText(value).then(function (ok) {
          setFeedback({
            scope: scope,
            kind: ok ? 'notice' : 'error',
            message: t(ok ? 'common.copied' : 'common.copyError'),
          })
        })
      }

      function toggleControl() {
        const current = control.status
        if (!current || !current.account.signedIn || isBusy('enable')) return
        const nextEnabled = !current.host.enabled
        runAction(
          'enable',
          'this',
          nextEnabled ? 'this.enableError' : 'this.disableError',
          function () {
            return postJson('/dsh-connections/control/enable', { enabled: nextEnabled })
          },
          function (payload) {
            if (!applyStatus(payload)) refreshControl()
            if (!nextEnabled) setLink(null)
            showNotice('this', t(nextEnabled ? 'this.enabledNotice' : 'this.disabledNotice'))
          },
        )
      }

      function generateLink() {
        const current = control.status
        if (!current || !current.account.signedIn || isBusy('link')) return
        runAction(
          'link',
          'this',
          'this.linkError',
          function () {
            return postJson('/dsh-connections/control/link', {})
          },
          function (payload) {
            if (!payload || typeof payload.link !== 'string' || payload.link === '') {
              showError('this', t('this.linkError'))
              return
            }
            setLink({ link: payload.link, guestDeviceId: stringField(payload.guestDeviceId) })
            showNotice('this', t('this.linkCreated'))
            refreshControl()
          },
        )
      }

      function removeGuest(deviceId) {
        const key = 'unpair-guest:' + deviceId
        if (isBusy(key)) return
        runAction(
          key,
          'this',
          'this.removeError',
          function () {
            return postJson('/dsh-connections/control/unpair', { deviceId: deviceId, side: 'guest' })
          },
          function (payload) {
            if (!applyStatus(payload)) refreshControl()
            showNotice('this', t('this.removedNotice'))
          },
        )
      }

      function pairWithLink() {
        const value = pairInput.trim()
        if (value === '') {
          showError('other', t('other.pairInputRequired'))
          return
        }
        const current = control.status
        if (!current || !current.account.signedIn || isBusy('pair')) return
        runAction(
          'pair',
          'other',
          'other.pairError',
          function () {
            return postJson('/dsh-connections/control/pair', { link: value })
          },
          function (payload) {
            setPairInput('')
            if (!payload || !payload.peer || typeof payload.peer !== 'object') {
              showError('other', t('other.pairError'))
              refreshControl()
              return
            }
            showNotice('other', t('other.pairSuccess'))
            refreshControl()
          },
        )
      }

      function connectPeer(deviceId) {
        const key = 'connect:' + deviceId
        if (isBusy(key)) return
        runAction(
          key,
          'other',
          'other.connectError',
          function () {
            return postJson('/dsh-connections/control/connect', { deviceId: deviceId })
          },
          function (payload) {
            const url = payload && typeof payload.url === 'string' ? payload.url : ''
            if (url === '') {
              showError('other', t('other.connectError'))
              return
            }
            setOpened(function (previous) {
              const next = Object.assign({}, previous)
              next[deviceId] = url
              return next
            })
            try {
              if (typeof window !== 'undefined' && typeof window.open === 'function') {
                window.open(url, '_blank', 'noopener,noreferrer')
              }
            } catch (error) {
              /* the URL is still shown so it can be opened manually */
            }
            showNotice('other', t('other.connectSuccess'))
            refreshControl()
          },
        )
      }

      function disconnectPeer(deviceId) {
        const key = 'disconnect:' + deviceId
        if (isBusy(key)) return
        runAction(
          key,
          'other',
          'other.disconnectError',
          function () {
            return postJson('/dsh-connections/control/disconnect', { deviceId: deviceId })
          },
          function (payload) {
            if (!applyStatus(payload)) refreshControl()
            setOpened(function (previous) {
              const next = Object.assign({}, previous)
              delete next[deviceId]
              return next
            })
            showNotice('other', t('other.disconnectedNotice'))
          },
        )
      }

      function removePeer(deviceId) {
        const key = 'unpair-peer:' + deviceId
        if (isBusy(key)) return
        runAction(
          key,
          'other',
          'other.removeError',
          function () {
            return postJson('/dsh-connections/control/unpair', { deviceId: deviceId, side: 'peer' })
          },
          function (payload) {
            if (!applyStatus(payload)) refreshControl()
            setOpened(function (previous) {
              const next = Object.assign({}, previous)
              delete next[deviceId]
              return next
            })
            showNotice('other', t('other.removedNotice'))
          },
        )
      }

      /* ------------------------------- Renderers ----------------------------- */
      function renderSshStatus(key) {
        const state = (sshTests && sshTests[key]) || { phase: 'idle' }
        const phase =
          state.phase === 'ok' || state.phase === 'fail' || state.phase === 'testing' ? state.phase : 'idle'
        let label = t('ssh.testIdle')
        if (phase === 'testing') label = t('ssh.testing')
        else if (phase === 'fail') label = t('ssh.testFail')
        else if (phase === 'ok') {
          label = typeof state.ms === 'number' ? t('ssh.testOkMs', { ms: state.ms }) : t('ssh.testOk')
        }
        return {
          phase: phase,
          label: label,
          detail: phase === 'fail' && typeof state.detail === 'string' ? state.detail : undefined,
        }
      }

      function renderSshRow(hostValue, key) {
        const state = renderSshStatus(key)
        return h(
          'div',
          { className: 'dsh-connections__row', key: key },
          h(
            'div',
            { className: 'dsh-connections__rowMain' },
            h('div', { className: 'dsh-connections__alias' }, hostValue.alias),
            h(
              'div',
              { className: 'dsh-connections__target', title: hostTarget(hostValue) },
              hostTarget(hostValue),
            ),
            h(
              'div',
              { className: 'dsh-connections__meta' },
              h('span', { className: 'dsh-connections__chip' }, t('ssh.source', { source: hostValue.source })),
              h(
                'span',
                { className: 'dsh-connections__identity' },
                hostValue.identityFile
                  ? t('ssh.identity', { path: hostValue.identityFile })
                  : t('ssh.identityDefault'),
              ),
            ),
            state.detail ? h('div', { className: 'dsh-connections__failDetail' }, state.detail) : null,
          ),
          h(
            'div',
            { className: 'dsh-connections__testCell' },
            h(
              'span',
              { className: 'dsh-connections__status', role: 'status', 'aria-live': 'polite' },
              h('span', { className: dotClass(state.phase), 'aria-hidden': true }),
              h('span', { className: statusTextClass(state.phase) }, state.label),
            ),
            h(
              'button',
              {
                type: 'button',
                className: 'dsh-connections__button',
                disabled: state.phase === 'testing',
                'aria-label': t('ssh.testAria', { alias: hostValue.alias }),
                onClick: function () { testConnection(key, hostValue.alias) },
              },
              t('ssh.test'),
            ),
          ),
        )
      }

      function renderSshBody() {
        if (sshView.phase === 'loading') {
          return h(
            'div',
            { className: 'dsh-connections__loading', role: 'status', 'aria-live': 'polite' },
            t('ssh.loading'),
          )
        }
        if (sshView.phase === 'error') {
          return h(
            'div',
            { className: 'dsh-connections__error', role: 'alert' },
            h(
              'div',
              { className: 'dsh-connections__errorText' },
              h('div', { className: 'dsh-connections__errorTitle' }, t('ssh.loadError')),
              h('div', { className: 'dsh-connections__muted' }, t('ssh.loadErrorHint')),
              typeof sshView.status === 'number'
                ? h(
                    'div',
                    { className: 'dsh-connections__muted' },
                    t('common.httpStatus', { status: sshView.status }),
                  )
                : null,
            ),
            h(
              'button',
              { type: 'button', className: 'dsh-connections__button', onClick: reloadSsh },
              t('common.retry'),
            ),
          )
        }
        const hosts = Array.isArray(sshView.hosts) ? sshView.hosts : []
        if (hosts.length === 0) {
          return h(
            'div',
            { className: 'dsh-connections__empty' },
            h('div', { className: 'dsh-connections__emptyTitle' }, t('ssh.emptyTitle')),
            h('div', { className: 'dsh-connections__muted' }, t('ssh.emptyBody')),
            h('pre', { className: 'dsh-connections__pre' }, t('ssh.emptyExample')),
            h('div', { className: 'dsh-connections__muted' }, t('ssh.emptyDirect')),
          )
        }
        return h(
          'div',
          { className: 'dsh-connections__card' },
          hosts.map(function (entry, index) {
            return renderSshRow(entry, entry.alias + '\u0000' + index)
          }),
        )
      }

      function renderSshWarnings() {
        if (sshView.phase !== 'ready' || !Array.isArray(sshView.warnings) || sshView.warnings.length === 0) {
          return null
        }
        return h(
          'div',
          { className: 'dsh-connections__warn', role: 'status' },
          h('div', { className: 'dsh-connections__warnTitle' }, t('ssh.warningsHeading')),
          h(
            'ul',
            { className: 'dsh-connections__warnList' },
            sshView.warnings.map(function (warning, index) {
              return h('li', { key: 'ssh-warning-' + index }, warning)
            }),
          ),
        )
      }

      function renderTool(name, description) {
        return h(
          'div',
          { className: 'dsh-connections__tool', key: name },
          h('span', { className: 'dsh-connections__toolName' }, name),
          h('span', { className: 'dsh-connections__toolDesc' }, description),
        )
      }

      function renderTools() {
        return h(
          'div',
          { className: 'dsh-connections__field' },
          h('div', { className: 'dsh-connections__fieldTitle' }, t('tools.heading')),
          h('p', { className: 'dsh-connections__hint' }, t('tools.intro')),
          h(
            'div',
            { className: 'dsh-connections__tools' },
            renderTool('ssh_exec', t('tools.exec.desc')),
            renderTool('ssh_open / ssh_send / ssh_read / ssh_close', t('tools.shell.desc')),
            renderTool('ssh_copy', t('tools.copy.desc')),
            renderTool('ssh_tunnel', t('tools.tunnel.desc')),
            renderTool('ssh_harness', t('tools.harness.desc')),
          ),
        )
      }

      function renderFeedback(scope) {
        if (!feedback || feedback.scope !== scope) return null
        const isError = feedback.kind === 'error'
        return h(
          'div',
          {
            className:
              'dsh-connections__feedback ' +
              (isError ? 'dsh-connections__feedback--error' : 'dsh-connections__feedback--notice'),
            role: isError ? 'alert' : 'status',
          },
          h('span', null, feedback.message),
          feedback.detail ? h('span', { className: 'dsh-connections__feedbackDetail' }, feedback.detail) : null,
        )
      }

      const status = control.status
      const host = status ? status.host : undefined
      const account = status ? status.account : undefined
      const signedIn = !!(account && account.signedIn)
      const pending = host && Array.isArray(host.pending) ? host.pending : []
      const paired = host && Array.isArray(host.paired) ? host.paired : []
      const peers = status && Array.isArray(status.peers) ? status.peers : []

      function accountDisplay() {
        if (!account) return t('common.unknown')
        if (!account.signedIn) return t('control.signedOut')
        return account.name || account.contact || account.id || t('common.unknown')
      }

      function renderSshSection() {
        return h(
          'section',
          { className: 'dsh-connections__section', key: 'ssh' },
          h(
            'div',
            { className: 'dsh-connections__sectionHead' },
            h('h2', { className: 'dsh-connections__heading' }, t('ssh.heading')),
            h(
              'button',
              {
                type: 'button',
                className: 'dsh-connections__button',
                onClick: reloadSsh,
                disabled: sshView.phase === 'loading',
              },
              t('common.reload'),
            ),
          ),
          h('p', { className: 'dsh-connections__intro' }, t('ssh.intro')),
          renderSshBody(),
          renderSshWarnings(),
          renderTools(),
        )
      }

      function renderControlGate() {
        if (control.phase === 'loading') {
          return h(
            'div',
            { className: 'dsh-connections__loading', key: 'control-loading', role: 'status', 'aria-live': 'polite' },
            t('control.loading'),
          )
        }
        return h(
          'div',
          { className: 'dsh-connections__error', key: 'control-error', role: 'alert' },
          h(
            'div',
            { className: 'dsh-connections__errorText' },
            h('div', { className: 'dsh-connections__errorTitle' }, t('control.loadError')),
            h('div', { className: 'dsh-connections__muted' }, t('control.loadErrorHint')),
            typeof control.errorStatus === 'number'
              ? h(
                  'div',
                  { className: 'dsh-connections__muted' },
                  t('common.httpStatus', { status: control.errorStatus }),
                )
              : null,
          ),
          h(
            'button',
            { type: 'button', className: 'dsh-connections__button', onClick: refreshControl },
            t('common.retry'),
          ),
        )
      }

      function renderListen(hostValue) {
        const address = hostValue.port
          ? hostValue.addresses.length > 0
            ? hostValue.addresses[0] + ':' + hostValue.port
            : ':' + hostValue.port
          : undefined
        return h(
          'div',
          { className: 'dsh-connections__field', key: 'listen' },
          h('div', { className: 'dsh-connections__fieldTitle' }, t('this.listenAddress')),
          h(
            'div',
            { className: 'dsh-connections__deviceMeta' },
            h('span', { className: 'dsh-connections__url' }, address || t('common.unknown')),
            h(
              'span',
              { className: 'dsh-connections__status' },
              h('span', { className: dotClass(hostValue.running ? 'ok' : 'idle'), 'aria-hidden': true }),
              h(
                'span',
                { className: statusTextClass(hostValue.running ? 'ok' : 'idle') },
                t(hostValue.running ? 'this.running' : 'this.notRunning'),
              ),
            ),
          ),
        )
      }

      function renderLinkArea() {
        return h(
          'div',
          { className: 'dsh-connections__field', key: 'link' },
          h(
            'div',
            { className: 'dsh-connections__actions' },
            h(
              'button',
              {
                type: 'button',
                className: 'dsh-connections__button',
                disabled: !signedIn || isBusy('link'),
                'aria-busy': isBusy('link'),
                onClick: generateLink,
              },
              t('this.generateLink'),
            ),
            link
              ? h(
                  'button',
                  {
                    type: 'button',
                    className: 'dsh-connections__button',
                    onClick: function () { copyValue(link.link, 'this') },
                  },
                  t('common.copy'),
                )
              : null,
          ),
          link
            ? h('textarea', {
                className: 'dsh-connections__codeBox',
                readOnly: true,
                rows: 3,
                value: link.link,
                'aria-label': t('this.linkLabel'),
                onFocus: function (event) {
                  try {
                    event.target.select()
                  } catch (error) {
                    /* selection is a nicety */
                  }
                },
              })
            : null,
          link ? h('p', { className: 'dsh-connections__hint' }, t('this.linkSecretHint')) : null,
        )
      }

      function renderPending(devices) {
        return h(
          'div',
          { className: 'dsh-connections__field', key: 'pending' },
          h('div', { className: 'dsh-connections__fieldTitle' }, t('this.pendingHeading')),
          h(
            'div',
            { className: 'dsh-connections__card' },
            devices.map(function (device) {
              return h(
                'div',
                { className: 'dsh-connections__listRow', key: device.deviceId },
                h(
                  'div',
                  { className: 'dsh-connections__listMain' },
                  h('div', { className: 'dsh-connections__listTitle' }, device.name || t('common.unknown')),
                ),
                h('span', { className: 'dsh-connections__hint' }, t('this.pendingWaiting')),
              )
            }),
          ),
        )
      }

      function renderPaired(devices) {
        return h(
          'div',
          { className: 'dsh-connections__field', key: 'paired' },
          h('div', { className: 'dsh-connections__fieldTitle' }, t('this.pairedHeading')),
          devices.length === 0
            ? h('p', { className: 'dsh-connections__hint' }, t('this.noPaired'))
            : h(
                'div',
                { className: 'dsh-connections__card' },
                devices.map(function (device) {
                  const key = 'unpair-guest:' + device.deviceId
                  return h(
                    'div',
                    { className: 'dsh-connections__listRow', key: device.deviceId },
                    h(
                      'div',
                      { className: 'dsh-connections__listMain' },
                      h('div', { className: 'dsh-connections__listTitle' }, device.name || t('common.unknown')),
                      h(
                        'div',
                        { className: 'dsh-connections__hint' },
                        device.lastSeenAt
                          ? t('this.lastSeen', { time: formatTime(device.lastSeenAt) })
                          : t('this.lastSeenNever'),
                      ),
                    ),
                    h(
                      'button',
                      {
                        type: 'button',
                        className: 'dsh-connections__button',
                        disabled: isBusy(key),
                        onClick: function () { removeGuest(device.deviceId) },
                      },
                      t('this.remove'),
                    ),
                  )
                }),
              ),
        )
      }

      function renderNotes() {
        const notes = status && Array.isArray(status.notes) ? status.notes : []
        if (notes.length === 0) return null
        return h(
          'div',
          { className: 'dsh-connections__warn', role: 'status', key: 'notes' },
          h('div', { className: 'dsh-connections__warnTitle' }, t('common.notes')),
          h(
            'ul',
            { className: 'dsh-connections__warnList' },
            notes.map(function (note, index) {
              return h('li', { key: 'control-note-' + index }, note)
            }),
          ),
        )
      }

      function renderControlThis() {
        const hostValue = host || {
          enabled: false,
          running: false,
          port: undefined,
          addresses: [],
          pending: [],
          paired: [],
        }
        return h(
          'section',
          { className: 'dsh-connections__section', key: 'control-this' },
          h('h2', { className: 'dsh-connections__heading' }, t('this.heading')),
          h(
            'div',
            { className: 'dsh-connections__body' },
            h(
              'div',
              { className: 'dsh-connections__accountRow' },
              h(
                'span',
                { className: 'dsh-connections__accountChip' },
                h('span', { className: 'dsh-connections__accountName' }, accountDisplay()),
                signedIn && account.contact && account.contact !== account.name
                  ? h('span', { className: 'dsh-connections__accountContact' }, account.contact)
                  : null,
              ),
              !signedIn ? h('span', { className: 'dsh-connections__hint' }, t('control.accountHint')) : null,
            ),
            !signedIn ? h('p', { className: 'dsh-connections__hint' }, t('this.signedOutHint')) : null,
            h(
              'div',
              { className: 'dsh-connections__switchRow' },
              h('span', { className: 'dsh-connections__switchLabel' }, t('this.allow')),
              h(
                'button',
                {
                  type: 'button',
                  className: 'dsh-connections__switch',
                  role: 'switch',
                  'aria-checked': hostValue.enabled,
                  'aria-label': t('this.allow'),
                  'aria-busy': isBusy('enable'),
                  disabled: !signedIn || isBusy('enable'),
                  onClick: toggleControl,
                },
                h('span', { className: 'dsh-connections__switchKnob', 'aria-hidden': true }),
              ),
            ),
            isBusy('enable') ? h('p', { className: 'dsh-connections__hint' }, t('common.busy')) : null,
            hostValue.enabled ? renderListen(hostValue) : null,
            hostValue.enabled ? renderLinkArea() : null,
            pending.length > 0 ? renderPending(pending) : null,
            renderPaired(paired),
            h(
              'div',
              { className: 'dsh-connections__warn', role: 'note' },
              h('div', { className: 'dsh-connections__warnTitle' }, t('this.warningTitle')),
              h('div', { className: 'dsh-connections__muted' }, t('this.warning')),
            ),
            renderNotes(),
            renderFeedback('this'),
          ),
        )
      }

      function renderPeerList(peerList) {
        return h(
          'div',
          { className: 'dsh-connections__field', key: 'peers' },
          h('div', { className: 'dsh-connections__fieldTitle' }, t('other.peersHeading')),
          h(
            'div',
            { className: 'dsh-connections__card' },
            peerList.map(function (peer) {
              const connected = peer.connected === true
              const connectKey = 'connect:' + peer.deviceId
              const disconnectKey = 'disconnect:' + peer.deviceId
              const unpairKey = 'unpair-peer:' + peer.deviceId
              const openedUrl = opened[peer.deviceId]
              return h(
                'div',
                { className: 'dsh-connections__deviceRow', key: peer.deviceId },
                h(
                  'div',
                  { className: 'dsh-connections__deviceHead' },
                  h('span', { className: 'dsh-connections__deviceName' }, peer.name || t('common.unknown')),
                  h(
                    'span',
                    { className: 'dsh-connections__status' },
                    h('span', { className: dotClass(connected ? 'ok' : 'idle'), 'aria-hidden': true }),
                    h(
                      'span',
                      { className: statusTextClass(connected ? 'ok' : 'idle') },
                      t(connected ? 'other.connected' : 'other.notConnected'),
                    ),
                  ),
                ),
                h(
                  'div',
                  { className: 'dsh-connections__deviceMeta' },
                  h('span', null, formatPeerAddress(peer)),
                  h(
                    'span',
                    null,
                    peer.lastConnectedAt
                      ? t('other.lastConnected', { time: formatTime(peer.lastConnectedAt) })
                      : t('other.lastConnectedNever'),
                  ),
                ),
                h(
                  'div',
                  { className: 'dsh-connections__actions' },
                  h(
                    'button',
                    {
                      type: 'button',
                      className: 'dsh-connections__button',
                      disabled: isBusy(connectKey),
                      'aria-busy': isBusy(connectKey),
                      onClick: function () { connectPeer(peer.deviceId) },
                    },
                    t('other.connectAndOpen'),
                  ),
                  h(
                    'button',
                    {
                      type: 'button',
                      className: 'dsh-connections__button',
                      disabled: !connected || isBusy(disconnectKey),
                      onClick: function () { disconnectPeer(peer.deviceId) },
                    },
                    t('other.disconnect'),
                  ),
                  h(
                    'button',
                    {
                      type: 'button',
                      className: 'dsh-connections__button',
                      disabled: isBusy(unpairKey),
                      onClick: function () { removePeer(peer.deviceId) },
                    },
                    t('other.remove'),
                  ),
                ),
                isBusy(connectKey) ? h('p', { className: 'dsh-connections__hint' }, t('common.busy')) : null,
                openedUrl
                  ? h(
                      'div',
                      { className: 'dsh-connections__field' },
                      h('div', { className: 'dsh-connections__fieldTitle' }, t('other.openUrlLabel')),
                      h(
                        'div',
                        { className: 'dsh-connections__actions' },
                        h('code', { className: 'dsh-connections__url' }, openedUrl),
                        h(
                          'button',
                          {
                            type: 'button',
                            className: 'dsh-connections__button',
                            onClick: function () { copyValue(openedUrl, 'other') },
                          },
                          t('common.copy'),
                        ),
                      ),
                      h('p', { className: 'dsh-connections__hint' }, t('other.popupBlockedHint')),
                    )
                  : null,
              )
            }),
          ),
        )
      }

      function renderControlOther() {
        return h(
          'section',
          { className: 'dsh-connections__section', key: 'control-other' },
          h('h2', { className: 'dsh-connections__heading' }, t('other.heading')),
          h(
            'div',
            { className: 'dsh-connections__body' },
            h('p', { className: 'dsh-connections__intro' }, t('other.intro')),
            h(
              'div',
              { className: 'dsh-connections__field', key: 'pair-input' },
              h('div', { className: 'dsh-connections__fieldTitle' }, t('other.linkLabel')),
              h('textarea', {
                className: 'dsh-connections__codeBox',
                rows: 3,
                value: pairInput,
                placeholder: t('other.linkPlaceholder'),
                'aria-label': t('other.linkLabel'),
                spellCheck: false,
                autoCapitalize: 'off',
                autoCorrect: 'off',
                onChange: function (event) { setPairInput(event.target.value) },
              }),
              h(
                'div',
                { className: 'dsh-connections__actions' },
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'dsh-connections__button',
                    disabled: !signedIn || isBusy('pair') || pairInput.trim() === '',
                    'aria-busy': isBusy('pair'),
                    onClick: pairWithLink,
                  },
                  t('other.pair'),
                ),
                pairInput !== ''
                  ? h(
                      'button',
                      {
                        type: 'button',
                        className: 'dsh-connections__button',
                        onClick: function () { setPairInput('') },
                      },
                      t('common.clear'),
                    )
                  : null,
              ),
              h('p', { className: 'dsh-connections__hint' }, t('other.linkPrivacy')),
            ),
            !signedIn ? h('p', { className: 'dsh-connections__hint' }, t('control.accountHint')) : null,
            renderFeedback('other'),
            peers.length === 0
              ? h(
                  'div',
                  { className: 'dsh-connections__empty', key: 'peers-empty' },
                  h('div', { className: 'dsh-connections__emptyTitle' }, t('other.emptyTitle')),
                  h('div', { className: 'dsh-connections__muted' }, t('other.empty')),
                )
              : renderPeerList(peers),
          ),
        )
      }

      function renderTabs() {
        const tabs = [
          { id: 'ssh', labelKey: 'tabs.ssh' },
          { id: 'this', labelKey: 'tabs.this' },
          { id: 'other', labelKey: 'tabs.other' },
        ]
        return h(
          'div',
          { className: 'dsh-connections__tabs', role: 'tablist', 'aria-label': t('tabs.aria') },
          tabs.map(function (tab) {
            const active = activeTab === tab.id
            return h(
              'button',
              {
                key: tab.id,
                type: 'button',
                role: 'tab',
                'aria-selected': active ? 'true' : 'false',
                className:
                  'dsh-connections__tab' + (active ? ' dsh-connections__tab--active' : ''),
                onClick: function () { setActiveTab(tab.id) },
              },
              t(tab.labelKey),
            )
          }),
        )
      }

      function renderControlPanel(which) {
        if (control.phase !== 'ready') return renderControlGate()
        return [
          control.stale
            ? h(
                'div',
                { className: 'dsh-connections__stale', key: 'control-stale', role: 'status' },
                t('control.stale'),
              )
            : null,
          which === 'this' ? renderControlThis() : renderControlOther(),
        ]
      }

      const activeContent =
        activeTab === 'ssh'
          ? renderSshSection()
          : activeTab === 'this'
            ? renderControlPanel('this')
            : renderControlPanel('other')

      return h(
        'div',
        { className: 'dsh-connections__root' },
        h('style', { key: 'dsh-connections-styles' }, STYLES),
        renderTabs(),
        h(
          'div',
          {
            className: 'dsh-connections__panel',
            key: 'dsh-connections-panel',
            role: 'tabpanel',
            'aria-label':
              activeTab === 'ssh'
                ? t('tabs.ssh')
                : activeTab === 'this'
                  ? t('tabs.this')
                  : t('tabs.other'),
          },
          activeContent,
        ),
      )
    }

    /* ------------------------------------------------------------------ *
     * Plugin body.                                                         *
     * ------------------------------------------------------------------ */
    function apply(ctx) {
      const locale = ctx.locale
      const slots = ctx.slots

      localeService = locale

      if (locale && typeof locale.register === 'function') {
        const registerDictionaries = function () {
          const disposers = []
          disposers.push(locale.register(NS, 'en', en))
          disposers.push(locale.register(NS, 'zh', zh))
          return function () {
            for (let index = disposers.length - 1; index >= 0; index -= 1) {
              const dispose = disposers[index]
              if (typeof dispose === 'function') dispose()
            }
          }
        }
        if (typeof ctx.effect === 'function') {
          ctx.effect(registerDictionaries, 'dsh-connections: dictionaries')
        } else {
          registerDictionaries()
        }
      }

      if (locale && typeof locale.bind === 'function') {
        t = locale.bind(NS)
      }

      if (slots && typeof slots.inject === 'function' && typeof slots.register === 'function') {
        slots.inject('settings.section', function () {
          return slots.register(
            {
              name: 'settings.section',
              id: 'connections',
              order: 30,
              label: function () { return t('section.label') },
            },
            ConnectionsPage,
          )
        })
      }
    }

    return {
      inject: ['slots', 'locale'],
      apply: apply,
    }
  },
})
