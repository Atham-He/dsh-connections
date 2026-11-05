# @local/dsh-connections

把「连接」能力加进当前 DeepSeek Harness（DSH Desktop）。设置 → **连接（Connections）** 页面分成三个明确的部分，互不混用：

1. **SSH** — 通过 OpenSSH 连接服务器。
2. **控制此电脑（Control this computer）** — 允许另一台登录同一 DeepSeek 账号的 DSH 控制这台电脑。
3. **控制其他设备（Control other devices）** — 配对并打开另一台登录同一账号的 DSH 的完整 Web UI。

连接方式参考 Codex 的远程连接：主机与凭据仍由本机管理；设备控制采用一次性配对链接 + 直连加密隧道（无云端 relay，因此两台机器需要经局域网/VPN 互通）。

## SSH（第一部分）

主机来源：

1. `~/.ssh/config` 中的具体 `Host` 别名（`HostName`、`User`、`Port`、`IdentityFile`、`ProxyJump` 会被读出用于展示）。
2. 直接目标：`user@host[:port]`。

认证/主机密钥完全沿用 OpenSSH（`BatchMode=yes`，不保存密码或私钥）。首次连接未知主机会失败并提示先手动 `ssh <alias>` 接受主机密钥。

| 工具 | 用途 |
|---|---|
| `ssh_hosts` | 列出 `~/.ssh/config` 中的主机 |
| `ssh_exec` | 一次性远程命令（无 PTY），返回 stdout/stderr/退出码 |
| `ssh_open` / `ssh_send` / `ssh_read` / `ssh_close` / `ssh_sessions` | 持久交互式 SSH 会话 |
| `ssh_copy` | `scp` 上传/下载（支持 `-r`） |
| `ssh_tunnel` | `ssh -N -L` 本地端口转发：`open` / `list` / `close` |
| `ssh_harness` | 通过 SSH 在远端启动 `dsh web`，转发到本地并返回 URL |

## 控制此电脑 / 控制其他设备（第二、三部分）

### 工作方式

- 两台机器都必须**登录同一个 DeepSeek 账号**（链接中带账号 id，控制端会校验；主机还会校验控制端声明的账号）。
- 在「控制此电脑」开启开关后，本机会监听一个 TCP 端口（默认 `39002`），并可以生成一条**一次性配对链接**。
- 在另一台机器的「控制其他设备」里粘贴链接完成配对；之后点击「连接并打开」会在本机起一个仅监听 `127.0.0.1` 的反向代理，并返回 `http://localhost:<port>/`，用浏览器打开即可看到**对端机器的完整 DSH Web UI**，操作方式与该机器本机一致。
- 隧道是点对点的 **AES-256-GCM 加密通道**（密钥由配对链接携带，连接时用 HKDF 派生双向密钥），不依赖云端；两台机器需要能互相访问（同一局域网，或 VPN/端口映射）。
- 配对记录持久化在 `$DSH_HOME/connections/control.json`（仅本机可读）。可在设置页随时移除配对设备；移除后其密钥立即失效。

### 安全边界

- 配对链接等同于一次性密码：通过可信渠道发送，不要公开发布；生成新链接会使旧链接失效。
- 打开「控制此电脑」等于把本机 DSH 的完整 Web UI 权限授予已配对设备；请只配对可信设备。
- 设备间传输使用对端 PSK 认证的加密通道；控制端本机代理只监听 `127.0.0.1`。浏览器 cookie 使用 `localhost` 域名与本地 `127.0.0.1` 的 DSH 隔离。
- 首次开启监听时 Windows 防火墙可能会询问；若另一台机器连不上，请允许该 TCP 端口的入站连接。
- 不读取、不保存、不转发 DeepSeek 账号 token；账号信息只用于显示与账号一致性校验。

### 智能体工具

| 工具 | 用途 |
|---|---|
| `remote_control` | `status` / `enable` / `disable` / `pairing_link` / `pair` / `connect` / `disconnect` / `unpair`；`connect` 返回可直接打开的 localhost URL |

例如：

- “用 `remote_control` 开启控制此电脑，生成配对链接”
- “用 `remote_control` 配对这条链接，然后连接并给我 URL”
- “用 `remote_control` 解除 PairTest 的配对”

## 已知限制

- 没有云端 relay / NAT 穿透：两台机器必须网络可达（局域网、VPN 或已做端口转发）。
- 配对通过复制链接完成（未内置二维码/手机配对）。
- `ssh_harness` 的远端启动流程假定 POSIX shell；Windows 远端暂不支持这套启动命令。
- 设备控制目前要求主机的 Web 载体是普通 HTTP（当前桌面版即如此）；HTTPS Web 载体尚未支持。
- 交互式 SSH 会话基于管道式 `ssh -tt`，不是本地 PTY，不支持窗口 resize/全屏 TUI 键序列。
- 设置页通过同源 `fetch` 调用 Host 路由；页面渲染依赖 DSH Web 客户端的 `settings.section` 槽位。

## 验证（开发环境）

- `node test/unit.test.mjs`：24 个测试通过（SSH 配置解析、exec/copy/会话/隧道/远端 harness）。
- `node test/control.test.mjs`：8 个测试通过（配对链接、状态迁移、AES-GCM 握手、错误密钥/未知设备拒绝、proxy 管道、HTTP 头重写）。
- 双实例端到端（本机 desktop + pairtest，两个 Electron Host，同一账号）：
  - `pair` → `connect` → 隧道返回 `http://localhost:<port>/`，该 URL 返回 200 且含 `__DSH_BOOT__`；
  - 隧道内静态资源（CSS/JS，约 0.9 MB）返回 200；
  - 双向都验证：desktop 控制 pairtest、pairtest 控制 desktop；
  - `disconnect` 关闭本地端口；`unpair` 后重连因密钥失效而失败；
  - 主机进程在异常连接、半开连接、握手垃圾数据下保持存活。
- 未在真实外网/跨机器网络环境验证；使用前请确认防火墙/VPN 与账号一致性。

## 开发期环境变量（可选）

- `DSH_CONNECTIONS_HOME`：控制状态目录（默认 `$DSH_HOME`，状态文件为 `<dir>/connections/control.json`）。用于同机双实例测试时隔离状态。
- `DSH_CONNECTIONS_DEVICE_NAME`：设备显示名（默认 `os.hostname()`）。
- `DSH_CONNECTIONS_DEBUG=1`：把控制层诊断日志写到 Host stderr（不含密钥/token）。
