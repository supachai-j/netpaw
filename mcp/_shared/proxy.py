#!/usr/bin/env python3
"""Lazy MCP stdio proxy (stdlib only) in front of a slow-starting server.

Why: some clients (Codex `exec`) build their tool list from the first seconds of a session and drop servers that answer
`initialize` late. This proxy answers `initialize` / `tools/list` / `ping` instantly from a cached, hash-checked tool list and
starts the real server only on the first `tools/call`.

What it does and does NOT do (reviewed: docs/imports/fwrule-analyzer.md, PROXY-REVIEW PX-1..PX-5):
- Only `tools/call` is forwarded, and only for tool names present in the cache. Every other method (resources/*, prompts/*,
  sampling, ...) gets -32601. `tools/call` params/results are forwarded as JSON, not edited.
- Before the first forwarded call the real server's tools/list is compared with the cache (sha256); a mismatch makes every
  tools/call fail closed (-32001).
- The child gets an allow-listed environment (see ALLOWED_ENV). This is hygiene, NOT a sandbox: the child still runs as the
  same user and can use the network. Tokens such as UV_PUBLISH_TOKEN / UV_INDEX_*_PASSWORD are not passed.
- Malformed input (non-object JSON, batches) gets -32600. A child that hangs is killed after a timeout.
- No shell; child started from an argv list. Server->client requests from the child are answered with -32601.

Usage: proxy.py [--expect-sha256 HEX] [--reject-xml-declarations] [--set-env K=V ...] --cache tools.cache.json -- <child command...>

Shared by every server (mcp/<name>/tools.cache.json); fwrule additionally uses --reject-xml-declarations and --set-env FOMC_MAX_RULESET_BYTES=...
"""
import hashlib, json, os, queue, re, subprocess, sys, threading, time

ALLOWED_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "XDG_CACHE_HOME", "XDG_DATA_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR",
               "USER", "LOGNAME", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_PYTHON", "UV_NO_PROGRESS", "UV_OFFLINE")
_XML_DECL = re.compile(r"<!\s*(doctype|entity|element|attlist|notation)", re.I)   # upstream strips DOCTYPE with one regex pass that can be bypassed by nesting (security review H2-1)


def has_xml_decl(o) -> bool:
    if isinstance(o, str): return bool(_XML_DECL.search(o))
    if isinstance(o, dict): return any(has_xml_decl(k) or has_xml_decl(v) for k, v in o.items())
    if isinstance(o, (list, tuple)): return any(has_xml_decl(v) for v in o)
    return False
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
START_TIMEOUT = float(os.environ.get("NETPAW_PROXY_START_TIMEOUT", "300"))   # first start may build a cold uv env
CALL_TIMEOUT = float(os.environ.get("NETPAW_PROXY_CALL_TIMEOUT", "120"))


def canon(tools): return json.dumps(sorted(tools, key=lambda t: t["name"]), sort_keys=True, separators=(",", ":"))
def tools_hash(tools): return hashlib.sha256(canon(tools).encode()).hexdigest()


def send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n"); sys.stdout.flush()


def err(i, code, msg): return {"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": msg}}


class Child:
    def __init__(self, argv, init_params, extra_env=None):
        env = {k: v for k, v in os.environ.items() if k in ALLOWED_ENV}
        for k, v in (extra_env or {}).items(): env.setdefault(k, v)   # values pinned in the registry; not user-overridable (the variable is not in ALLOWED_ENV)
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, env=env, text=True, bufsize=1)
        self.q = queue.Queue(); self.n = 0
        threading.Thread(target=self._reader, daemon=True).start()
        self.call("initialize", init_params, START_TIMEOUT)
        self.notify("notifications/initialized")

    def _reader(self):
        for line in self.p.stdout: self.q.put(line)
        self.q.put(None)

    def _write(self, o): self.p.stdin.write(json.dumps(o, separators=(",", ":")) + "\n"); self.p.stdin.flush()

    def notify(self, method, params=None):
        self._write({"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})})

    def call(self, method, params=None, timeout=CALL_TIMEOUT):
        self.n += 1; rid = f"p{self.n}"
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, **({"params": params} if params is not None else {})})
        end = time.monotonic() + timeout      # H5-3: one deadline for the whole call; notifications from the child do not extend it
        while True:
            try: line = self.q.get(timeout=max(0.0, end - time.monotonic()))
            except queue.Empty: self.kill(); raise TimeoutError(f"child did not answer {method} within {timeout:.0f}s")
            if line is None: raise RuntimeError("child exited")
            try: m = json.loads(line)
            except (ValueError, RecursionError): continue      # H5-2: deeply nested JSON must not kill the proxy
            if not isinstance(m, dict): continue
            if m.get("id") == rid and ("result" in m or "error" in m): return m
            if "method" in m and "id" in m:   # server->client request: we support none
                self._write(err(m["id"], -32601, "client does not support server requests"))
            # notifications from the child are dropped

    def kill(self):
        try: self.p.kill()
        except Exception: pass


def main():
    a = sys.argv[1:]
    if "--" not in a: sys.exit("usage: proxy.py [--expect-sha256 HEX] --cache FILE -- CMD...")
    opts, argv = a[:a.index("--")], a[a.index("--") + 1:]
    usage = "usage: proxy.py [--expect-sha256 HEX] [--reject-xml-declarations] [--set-env K=V ...] --cache FILE -- CMD..."
    expect, cache_path, reject_xml, extra_env = None, None, False, {}
    i = 0
    while i < len(opts):
        o = opts[i]
        if o == "--expect-sha256" and i + 1 < len(opts): expect = opts[i + 1].lower(); i += 2
        elif o == "--cache" and i + 1 < len(opts): cache_path = opts[i + 1]; i += 2
        elif o == "--reject-xml-declarations": reject_xml = True; i += 1
        elif o == "--set-env" and i + 1 < len(opts) and re.fullmatch(r"[A-Z][A-Z0-9_]*=[^\x00]*", opts[i + 1]):
            k, v = opts[i + 1].split("=", 1); extra_env[k] = v; i += 2
        else: sys.exit(usage)
    if cache_path is None or not argv: sys.exit(usage)
    cache = json.load(open(cache_path))
    if tools_hash(cache["tools"]) != cache["sha256"]: sys.exit("tools cache corrupted (sha256 mismatch)")
    # PX-7: the cache file vouches for itself, so an attacker who edits tools and recomputes sha256 wins. The expected hash is pinned in the
    # agent's config (copied from mcp/servers.json at install time), a different place from the cache file.
    if expect is not None and cache["sha256"] != expect: sys.exit("tools cache does not match the pinned --expect-sha256 (changed tool definitions need review)")
    names = {t["name"] for t in cache["tools"]}
    st = {"child": None, "ok": None, "init": None}

    def ensure():
        if st["child"] is None or st["child"].p.poll() is not None:
            st["child"], st["ok"] = None, None
            c = Child(argv, st["init"], extra_env); r = c.call("tools/list")
            live = r.get("result", {}).get("tools", [])
            st["ok"] = (tools_hash(live) == cache["sha256"]); st["child"] = c
            if not st["ok"]: sys.stderr.write("netpaw proxy: live tools/list differs from cache; refusing tools/call\n")
        return st["child"]

    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: m = json.loads(line)
        except (ValueError, RecursionError): send(err(None, -32700, "parse error")); continue      # H5-2
        if not isinstance(m, dict) or not isinstance(m.get("method"), str):
            send(err(m.get("id") if isinstance(m, dict) else None, -32600, "invalid request (batches/non-requests are not supported)")); continue
        i, method, params = m.get("id"), m["method"], m.get("params")
        if method == "initialize":
            pv = (params or {}).get("protocolVersion") if isinstance(params, dict) else None
            pv = pv if pv in SUPPORTED_PROTOCOLS else "2025-03-26"
            st["init"] = {**(params if isinstance(params, dict) else {}), "protocolVersion": pv}
            send({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": pv, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": cache["serverInfo"]}})
        elif i is None: continue            # notifications (initialized, cancelled, ...) are ignored
        elif method == "ping": send({"jsonrpc": "2.0", "id": i, "result": {}})
        elif method == "tools/list": send({"jsonrpc": "2.0", "id": i, "result": {"tools": cache["tools"]}})
        elif method == "tools/call":
            if not isinstance(params, dict) or params.get("name") not in names:
                send(err(i, -32602, "unknown tool")); continue
            if st["init"] is None: send(err(i, -32002, "initialize first")); continue
            if reject_xml and has_xml_decl(params.get("arguments")): send(err(i, -32602, "XML DOCTYPE/ENTITY declarations are not accepted in tool arguments")); continue
            try:
                c = ensure()
                if not st["ok"]: send(err(i, -32001, "tool list changed upstream; regenerate tools cache and re-review")); continue
                r = c.call("tools/call", params); r["id"] = i; send(r)
            except Exception as e:
                if st["child"]: st["child"].kill()
                st["child"] = None
                send(err(i, -32003, f"proxy: {type(e).__name__}: {e}"))
        else: send(err(i, -32601, f"method not supported by this proxy: {method}"))
    if st["child"]: st["child"].kill()

if __name__ == "__main__":
    main()
