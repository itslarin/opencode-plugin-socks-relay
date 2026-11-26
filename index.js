/**
 * opencode-plugin-socks-relay
 *
 * OpenCode V2 server plugin with two modes, both backed by a SOCKS5 proxy
 * (typically `ssh -N -D 1080 user@server`).
 *
 * MODE "router" (default) — recommended
 *   Starts a loopback HTTP CONNECT proxy and sets HTTPS_PROXY/HTTP_PROXY for
 *   the OpenCode server process. Hosts listed in `tunnel` are sent through the
 *   SOCKS5 tunnel; every other host is connected directly. Because the proxy
 *   only tunnels, TLS stays end-to-end and protocol/body size never matters.
 *   Providers that are not blocked by the DPI are not affected at all.
 *
 * MODE "relay" — legacy
 *   Starts a loopback origin server that forwards to fixed upstreams. Point a
 *   provider's `settings.baseURL` at http://127.0.0.1:<port>/<name>/v1.
 *   Useful when the SOCKS proxy is not available and only TLS 1.2 works.
 *
 * Configuration file: ~/.config/opencode/socks-routes.json
 *
 *   {
 *     "mode": "router",
 *     "port": 8789,
 *     "socks": "127.0.0.1:1080",
 *     "tunnel": ["taynik.store", "api.synthetic.new"]
 *   }
 *
 * For mode "relay":
 *
 *   {
 *     "mode": "relay",
 *     "port": 8788,
 *     "socks": "127.0.0.1:1080",
 *     "tlsMaxVersion": "TLSv1.2",
 *     "upstreams": { "taynik": "taynik.store:443" }
 *   }
 */

import http from "node:http"
import https from "node:https"
import net from "node:net"
import tls from "node:tls"
import { appendFileSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { homedir, tmpdir } from "node:os"

const TAG = "[socks-relay]"
const MARKER = "opencode-plugin-socks-relay"
const HEALTH_PATH = "/__relay/health"
const CONFIG_PATH = process.env.OPENCODE_SOCKS_ROUTES || join(homedir(), ".config", "opencode", "socks-routes.json")
const DEBUG_LOG = join(tmpdir(), "opencode", "socks-relay.log")

const DEFAULTS = {
  mode: "router",
  port: 8789,
  socks: "127.0.0.1:1080",
  tunnel: [],
  upstreams: {},
  tlsMaxVersion: "TLSv1.2",
  username: undefined,
  password: undefined,
}

const HOP_BY_HOP = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
])

const state = {
  server: null,
  port: null,
  refs: 0,
  mode: null,
  socks: null,
  credentials: {},
  tlsMaxVersion: "TLSv1.2",
  tunnel: [],
  upstreams: {},
  requests: 0,
  recent: [],
}

function log(message) {
  console.log(TAG, message)
  try {
    appendFileSync(DEBUG_LOG, `${new Date().toISOString()} ${message}\n`)
  } catch {}
}

function parseHostPort(value, defaultPort) {
  const text = String(value).trim()
  const index = text.lastIndexOf(":")
  if (index > 0 && !text.startsWith("[")) {
    return { host: text.slice(0, index), port: Number(text.slice(index + 1)) || defaultPort }
  }
  return { host: text, port: defaultPort }
}

function loadConfig() {
  let fileConfig = {}
  try {
    fileConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf8"))
  } catch (err) {
    if (err && err.code !== "ENOENT") log(`cannot read ${CONFIG_PATH}: ${err.message}`)
  }
  const config = { ...DEFAULTS, ...fileConfig }
  config.port = Number(config.port) || DEFAULTS.port
  config.socks = parseHostPort(config.socks ?? DEFAULTS.socks, 1080)
  config.tunnel = Array.isArray(config.tunnel) ? config.tunnel.map((item) => String(item).toLowerCase()) : []
  config.upstreams = config.upstreams && typeof config.upstreams === "object" ? config.upstreams : {}
  return config
}

// ---------------------------------------------------------------- SOCKS5 client

/** Reads exactly `n` bytes in paused mode, so no byte can be lost between steps. */
async function readExactlyPaused(socket, n, timeoutMs = 15000) {
  const chunks = []
  let have = 0
  const deadline = Date.now() + timeoutMs

  while (have < n) {
    const chunk = socket.read(n - have)
    if (chunk && chunk.length > 0) {
      chunks.push(chunk)
      have += chunk.length
      continue
    }

    const left = deadline - Date.now()
    if (left <= 0) throw new Error(`SOCKS5 timeout after ${timeoutMs}ms`)

    await new Promise((resolve, reject) => {
      const cleanup = () => {
        clearTimeout(timer)
        socket.off("readable", onReadable)
        socket.off("error", onError)
        socket.off("close", onClose)
      }
      const onReadable = () => {
        cleanup()
        resolve()
      }
      const onError = (err) => {
        cleanup()
        reject(err)
      }
      const onClose = () => {
        cleanup()
        reject(new Error("SOCKS5 connection closed"))
      }
      const timer = setTimeout(() => {
        cleanup()
        reject(new Error(`SOCKS5 timeout after ${timeoutMs}ms`))
      }, left)
      socket.on("readable", onReadable)
      socket.on("error", onError)
      socket.on("close", onClose)
    })
  }

  return Buffer.concat(chunks, n)
}

async function socksConnect({ socks, target, username, password, timeoutMs = 15000 }) {
  const socket = net.connect({ host: socks.host, port: socks.port, family: 4 })
  socket.setNoDelay(true)

  try {
    await new Promise((resolve, reject) => {
      const onError = (err) => reject(err)
      socket.once("connect", () => {
        socket.off("error", onError)
        resolve()
      })
      socket.once("error", onError)
      setTimeout(() => reject(new Error(`SOCKS5 connect timeout to ${socks.host}:${socks.port}`)), timeoutMs)
    })

    const auth = username != null && username !== ""
    const methods = auth ? [0x00, 0x02] : [0x00]
    socket.write(Buffer.from([0x05, methods.length, ...methods]))

    const greeting = await readExactlyPaused(socket, 2, timeoutMs)
    if (greeting[0] !== 0x05) throw new Error("SOCKS5: unsupported protocol version")
    if (greeting[1] === 0xff) throw new Error("SOCKS5: server rejected all auth methods")

    if (greeting[1] === 0x02) {
      if (!auth) throw new Error("SOCKS5: server requires username/password")
      const user = Buffer.from(username)
      const pass = Buffer.from(password ?? "")
      socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]))
      const authReply = await readExactlyPaused(socket, 2, timeoutMs)
      if (authReply[1] !== 0x00) throw new Error("SOCKS5: authentication failed")
    }

    const host = Buffer.from(target.host)
    const port = Buffer.alloc(2)
    port.writeUInt16BE(target.port)
    socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]), host, port]))

    const reply = await readExactlyPaused(socket, 4, timeoutMs)
    if (reply[0] !== 0x05) throw new Error("SOCKS5: bad reply version")
    if (reply[1] !== 0x00) throw new Error(`SOCKS5: CONNECT failed (code ${reply[1]})`)

    let skip = 0
    if (reply[3] === 0x01) skip = 4
    else if (reply[3] === 0x04) skip = 16
    else if (reply[3] === 0x03) {
      const length = await readExactlyPaused(socket, 1, timeoutMs)
      skip = length[0]
    } else throw new Error("SOCKS5: unknown address type in reply")

    await readExactlyPaused(socket, skip + 2, timeoutMs)
    return socket
  } catch (err) {
    socket.destroy()
    throw err
  }
}

// ---------------------------------------------------------------- router mode

function matchesTunnel(host) {
  const name = host.toLowerCase()
  return state.tunnel.some((pattern) => name === pattern || name.endsWith(`.${pattern}`))
}

function openTunnel(host, port) {
  if (matchesTunnel(host)) {
    return socksConnect({
      socks: state.socks,
      target: { host, port },
      username: state.credentials.username,
      password: state.credentials.password,
    }).then((socket) => ({ socket, route: "socks" }))
  }
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port, family: 4 })
    socket.once("connect", () => resolve({ socket, route: "direct" }))
    socket.once("error", reject)
  })
}

function handleConnect(req, clientSocket, head) {
  const { host, port } = parseHostPort(req.url.replace(/^\[|\]$/g, ""), 443)
  const started = Date.now()

  state.requests += 1
  state.recent.push({ at: started, host, port })
  if (state.recent.length > 10) state.recent.shift()

  openTunnel(host, port)
    .then(({ socket, route }) => {
      if (typeof clientSocket.setNoDelay === "function") clientSocket.setNoDelay(true)
      if (typeof socket.setNoDelay === "function") socket.setNoDelay(true)
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n")
      if (head && head.length > 0) socket.write(head)
      socket.pipe(clientSocket)
      clientSocket.pipe(socket)
      socket.on("error", (err) => {
        log(`tunnel error ${route} ${host}:${port}: ${err.message}`)
        clientSocket.destroy()
      })
      clientSocket.on("error", (err) => {
        log(`client error ${route} ${host}:${port}: ${err.message}`)
        socket.destroy()
      })
    })
    .catch((err) => {
      log(`connect failed for ${host}:${port}: ${err.message}`)
      try {
        clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      } catch {}
    })
}

function renderHealth() {
  return JSON.stringify({
    app: MARKER,
    pid: process.pid,
    mode: state.mode,
    port: state.port,
    socks: { host: state.socks.host, port: state.socks.port },
    tunnel: state.tunnel,
    upstreams: Object.fromEntries(
      Object.entries(state.upstreams).map(([name, target]) => [name, `${target.host}:${target.port}`]),
    ),
    requests: state.requests,
    recent: state.recent,
  })
}

function makeRouter() {
  const server = http.createServer((req, res) => {
    const path = (req.url ?? "").split("?")[0]
    if (path === HEALTH_PATH || path.endsWith(HEALTH_PATH)) {
      res.writeHead(200, { "content-type": "application/json" })
      res.end(renderHealth())
      return
    }
    res.writeHead(501, { "content-type": "application/json" })
    res.end(JSON.stringify({ error: { type: "unsupported", message: "only CONNECT is supported" } }))
  })
  server.on("connect", handleConnect)
  return server
}

function applyProxyEnv(port) {
  const url = `http://127.0.0.1:${port}`
  const noProxyValues = new Set(
    String(process.env.NO_PROXY ?? process.env.no_proxy ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
  )
  for (const item of ["localhost", "127.0.0.1", "::1"]) noProxyValues.add(item)
  const noProxy = Array.from(noProxyValues).join(",")

  process.env.HTTPS_PROXY = url
  process.env.https_proxy = url
  process.env.HTTP_PROXY = url
  process.env.http_proxy = url
  process.env.NO_PROXY = noProxy
  process.env.no_proxy = noProxy
  log(`HTTPS_PROXY=${url} (NO_PROXY=${noProxy})`)
}

// ---------------------------------------------------------------- relay mode

function resolveUpstream(url) {
  const queryIndex = url.indexOf("?")
  const path = queryIndex === -1 ? url : url.slice(0, queryIndex)
  const query = queryIndex === -1 ? "" : url.slice(queryIndex)
  const segments = path.split("/").filter(Boolean)

  if (segments.length >= 2) {
    const name = segments[0]
    const target = state.upstreams[name]
    if (target) return { name, target, path: "/" + segments.slice(1).join("/") + query }
  }

  const fallbackName = Object.keys(state.upstreams)[0]
  if (!fallbackName) return null
  return { name: fallbackName, target: state.upstreams[fallbackName], path: url }
}

function tlsOverSocks(target, tlsMaxVersion) {
  return new Promise((resolve, reject) => {
    socksConnect({
      socks: state.socks,
      target,
      username: state.credentials.username,
      password: state.credentials.password,
    })
      .then((raw) => {
        const socket = tls.connect({
          socket: raw,
          servername: target.host,
          ALPNProtocols: ["http/1.1"],
          minVersion: "TLSv1.2",
          maxVersion: tlsMaxVersion,
        })
        socket.once("secureConnect", () => resolve(socket))
        socket.once("error", (err) => {
          raw.destroy()
          reject(err)
        })
      })
      .catch(reject)
  })
}

function handleRelay(req, res) {
  const path = (req.url ?? "").split("?")[0]
  if (path === HEALTH_PATH || path.endsWith(HEALTH_PATH)) {
    res.writeHead(200, { "content-type": "application/json" })
    res.end(renderHealth())
    return
  }

  const resolved = req.url ? resolveUpstream(req.url) : null
  if (!resolved) {
    res.writeHead(502, { "content-type": "application/json" })
    res.end(JSON.stringify({ error: { type: "relay_error", message: "no upstream configured" } }))
    return
  }

  state.requests += 1
  state.recent.push({ at: Date.now(), method: req.method, path: req.url, upstream: resolved.name })
  if (state.recent.length > 10) state.recent.shift()

  const headers = {}
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    if (HOP_BY_HOP.has(name.toLowerCase())) continue
    headers[name] = value
  }
  headers.host = resolved.target.port === 443 ? resolved.target.host : `${resolved.target.host}:${resolved.target.port}`

  const upstream = https.request(
    {
      host: resolved.target.host,
      port: resolved.target.port,
      path: resolved.path,
      method: req.method,
      headers,
      createConnection: (_options, callback) => {
        tlsOverSocks(resolved.target, state.tlsMaxVersion)
          .then((socket) => callback(null, socket))
          .catch((err) => callback(err))
      },
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers)
      if (typeof res.flushHeaders === "function") res.flushHeaders()
      upstreamRes.pipe(res)
      upstreamRes.on("error", (err) => res.destroy(err))
    },
  )

  upstream.on("error", (err) => {
    log(`relay failed (${resolved.name} ${req.method} ${resolved.path}): ${err.message}`)
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json" })
      res.end(JSON.stringify({ error: { type: "relay_error", message: `${resolved.name}: ${err.message}` } }))
    } else {
      res.destroy(err)
    }
  })

  req.on("error", (err) => upstream.destroy(err))
  req.pipe(upstream)
}

// ---------------------------------------------------------------- lifecycle

function listen(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (err) => reject(err)
    server.once("error", onError)
    server.listen(port, "127.0.0.1", () => {
      server.off("error", onError)
      resolve()
    })
  })
}

function checkExisting(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: HEALTH_PATH, timeout: 1500 }, (res) => {
      let body = ""
      res.on("data", (chunk) => (body += chunk))
      res.on("end", () => resolve(body.includes(MARKER)))
      res.on("error", () => resolve(false))
    })
    req.on("error", () => resolve(false))
    req.on("timeout", () => {
      req.destroy()
      resolve(false)
    })
  })
}

async function ensureServer(config) {
  state.mode = config.mode
  state.socks = config.socks
  state.credentials = { username: config.username, password: config.password }
  state.tlsMaxVersion = config.tlsMaxVersion
  state.tunnel = config.tunnel
  state.upstreams = Object.fromEntries(
    Object.entries(config.upstreams).map(([name, value]) => [name, parseHostPort(value, 443)]),
  )

  if (state.server) {
    state.refs += 1
    if (config.mode === "router") applyProxyEnv(state.port)
    return { port: state.port, owned: false }
  }

  const server = config.mode === "relay" ? http.createServer(handleRelay) : makeRouter()

  let bound = false
  let lastError = null
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      await listen(server, config.port)
      bound = true
      break
    } catch (err) {
      lastError = err
      if (!err || err.code !== "EADDRINUSE") {
        log(`cannot listen on 127.0.0.1:${config.port}: ${err && err.message}`)
        return null
      }
      await new Promise((resolve) => setTimeout(resolve, 700))
    }
  }

  if (!bound) {
    if (await checkExisting(config.port)) {
      state.port = config.port
      state.refs += 1
      log(`port ${config.port} already served by another instance, reusing it`)
      if (config.mode === "router") applyProxyEnv(config.port)
      return { port: config.port, owned: false }
    }
    log(`cannot listen on 127.0.0.1:${config.port}: ${lastError && lastError.message}`)
    return null
  }

  state.server = server
  state.port = config.port
  state.refs = 1

  if (config.mode === "relay") {
    const upstreamText = Object.entries(state.upstreams)
      .map(([name, target]) => `${name}->${target.host}:${target.port}`)
      .join(", ")
    log(`relay listening on http://127.0.0.1:${config.port} via SOCKS5 ${config.socks.host}:${config.socks.port} (${upstreamText})`)
  } else {
    log(
      `router listening on http://127.0.0.1:${config.port} via SOCKS5 ${config.socks.host}:${config.socks.port}; tunnel: ${
        state.tunnel.length > 0 ? state.tunnel.join(", ") : "(none)"
      }`,
    )
    applyProxyEnv(config.port)
  }

  return { port: config.port, owned: true }
}

function releaseServer(owned) {
  state.refs = Math.max(0, state.refs - 1)
  // The listener lives until the server process exits: closing it on plugin
  // cleanup makes the proxy disappear during config reloads, because the next
  // module instance can already see the port in use.
  if (owned && state.refs === 0) log("plugin unloaded; proxy keeps running until the server exits")
  return Promise.resolve()
}

export default {
  id: "socks-relay",

  async setup(ctx) {
    const config = loadConfig()
    if (config.mode === "router" && config.tunnel.length === 0) {
      log(`no hosts in "tunnel" (${CONFIG_PATH}); nothing to proxy`)
      return
    }
    const proxy = await ensureServer(config)
    if (!proxy) return

    return async () => {
      await releaseServer(proxy.owned)
    }
  },
}