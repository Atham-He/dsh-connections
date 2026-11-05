/**
 * Focused security + behaviour checks for the device-control core.
 *
 * Run: node plugins/dsh-connections/test/control.test.mjs
 */
import assert from 'node:assert/strict'
import net from 'node:net'
import { randomBytes } from 'node:crypto'
import {
  PAIRING_LINK_PREFIX,
  decodePairingLink,
  encodePairingLink,
  newPsk,
  normalizeState,
} from '../lib/control/state.js'
import {
  connectPsk,
  createPskServer,
  pipeSockets,
  readJsonLine,
  rewriteRequestHead,
  rewriteResponseHead,
  serveTunnelConnection,
  writeJsonLine,
} from '../lib/control/tunnel.js'

let passed = 0
const failures = []

async function test(name, fn) {
  try {
    await fn()
    passed += 1
    console.log(`ok - ${name}`)
  } catch (error) {
    failures.push({ name, error })
    console.log(`not ok - ${name}: ${error instanceof Error ? error.message : String(error)}`)
  }
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server.address().port))
  })
}

async function pskPair(options = {}) {
  const psk = randomBytes(32)
  const identity = options.identity ?? 'guest-test-1'
  const pskServer = createPskServer({
    lookupPsk(id) {
      return id === identity ? { psk, identity } : null
    },
    onConnection: options.onConnection ?? (() => {}),
    log: () => {},
  })
  const port = await listen(pskServer)
  return { psk, identity, pskServer, port }
}

await test('pairing link round-trips and rejects tampering', () => {
  const host = { id: 'host-1', name: 'Host', addresses: ['192.168.1.5', '127.0.0.1'], port: 39002 }
  const guest = { id: 'guest-1', psk: newPsk() }
  const link = encodePairingLink({ accountId: 'acct-1', host, guest, createdAt: Date.now() })
  assert.ok(link.startsWith(PAIRING_LINK_PREFIX))
  const payload = decodePairingLink(link)
  assert.equal(payload.accountId, 'acct-1')
  assert.equal(payload.host.id, 'host-1')
  assert.equal(payload.guest.id, 'guest-1')
  assert.equal(payload.guest.psk, guest.psk)
  assert.throws(() => decodePairingLink(link.slice(0, -3)), /invalid|损坏|无效/i)
  assert.throws(() => decodePairingLink('not-a-link'), /invalid|无效/i)
})

await test('state normalization preserves guest auth identity and drops bad peers', () => {
  const state = normalizeState(
    {
      version: 1,
      thisDevice: { id: 'this-1', name: 'This' },
      host: { enabled: false, port: 39002, pending: {}, paired: {} },
      peers: {
        'host-1': {
          deviceId: 'host-1',
          guestId: 'guest-1',
          name: 'Host',
          addresses: ['127.0.0.1'],
          port: 39002,
          psk: newPsk(),
          accountId: 'acct-1',
          webPort: 12345,
        },
        bad: { deviceId: 'bad', psk: 'nope' },
      },
    },
    { name: 'This' },
  )
  assert.equal(state.peers['host-1'].guestId, 'guest-1')
  assert.equal(state.peers.bad, undefined)
})

await test('PSK channel completes hello exchange', async () => {
  const { psk, identity, pskServer, port } = await pskPair({
    onConnection(channel, id) {
      void serveTunnelConnection(
        channel,
        id,
        {
          hello: () => ({ host: { id: 'host-1', name: 'Host' }, webPort: 12345 }),
        },
        { log: () => {} },
      )
    },
  })
  const channel = await connectPsk({ host: '127.0.0.1', port, psk, identity, timeoutMs: 3000 })
  await writeJsonLine(channel, { op: 'hello' })
  const reply = await readJsonLine(channel, { timeoutMs: 3000 })
  assert.equal(reply.ok, true)
  assert.equal(reply.host.id, 'host-1')
  channel.destroy()
  pskServer.close()
})

await test('wrong key is rejected', async () => {
  const { identity, pskServer, port } = await pskPair()
  await assert.rejects(
    connectPsk({ host: '127.0.0.1', port, psk: randomBytes(32), identity, timeoutMs: 2000 }),
    /握手|加密|认证|closed|failed/i,
  )
  pskServer.close()
})

await test('unknown identity is rejected', async () => {
  const { psk, pskServer, port } = await pskPair()
  await assert.rejects(
    connectPsk({ host: '127.0.0.1', port, psk, identity: 'unknown-guest', timeoutMs: 2000 }),
    /握手|加密|认证|closed|failed/i,
  )
  pskServer.close()
})

await test('proxy mode carries raw bytes through pipeSockets', async () => {
  const upstream = net.createServer((socket) => {
    socket.on('data', (data) => socket.write(Buffer.concat([Buffer.from('ECHO:'), data])))
  })
  const upstreamPort = await listen(upstream)
  const { psk, identity, pskServer, port } = await pskPair({
    onConnection(channel) {
      void serveTunnelConnection(
        channel,
        identity,
        {
          proxy: () => ({ webPort: upstreamPort }),
        },
        {
          onProxy(tunnel) {
            const target = net.connect({ host: '127.0.0.1', port: upstreamPort })
            pipeSockets(tunnel, target)
          },
          log: () => {},
        },
      )
    },
  })
  const channel = await connectPsk({ host: '127.0.0.1', port, psk, identity, timeoutMs: 3000 })
  await writeJsonLine(channel, { op: 'proxy' })
  assert.equal((await readJsonLine(channel, { timeoutMs: 3000 })).ok, true)
  channel.resume()
  channel.write('PING')
  const echoed = await new Promise((resolve, reject) => {
    channel.once('data', (data) => resolve(data.toString()))
    channel.once('error', reject)
    setTimeout(() => reject(new Error('echo timeout')), 3000)
  })
  assert.equal(echoed, 'ECHO:PING')
  channel.destroy()
  pskServer.close()
  upstream.close()
})

await test('request head rewrite fixes loopback authority and injects the session cookie', () => {
  const rewritten = rewriteRequestHead(
    'GET / HTTP/1.1\r\nHost: localhost:40000\r\nOrigin: http://localhost:40000\r\nConnection: keep-alive\r\nCookie: a=b\r\n\r\n',
    { webPort: 39011, sessionCookie: 'dsh=token' },
  )
  assert.match(rewritten.text, /Host: 127\.0\.0\.1:39011/)
  assert.match(rewritten.text, /Origin: http:\/\/127\.0\.0\.1:39011/)
  assert.match(rewritten.text, /Connection: close/)
  assert.match(rewritten.text, /Cookie: a=b; dsh=token/)
})

await test('response head rewrite maps host Location to localhost', () => {
  const rewritten = rewriteResponseHead('HTTP/1.1 303 See Other\r\nLocation: http://127.0.0.1:39011/\r\nContent-Length: 0\r\n\r\n', {
    webPort: 39011,
    localPort: 40000,
  })
  assert.equal(rewritten.status, 303)
  assert.match(rewritten.text, /Location: http:\/\/localhost:40000\//)
})

console.log(`\n${passed} passed, ${failures.length} failed`)
if (failures.length > 0) {
  for (const failure of failures) console.error(failure.error)
  process.exit(1)
}
process.exit(0)
