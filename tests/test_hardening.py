"""Findings from the tester cross-review (EV-1..EV-5, WK-1..WK-4, E-1/E-2) as regression tests."""
import json, pathlib, sys, time, unittest, io
R = pathlib.Path(__file__).resolve().parent.parent
for d in ("eve-lab", "wikipedia", "rfc-lookup", "_shared"): sys.path.insert(0, str(R / "mcp" / d))
import eve_core as eve, wiki_core as wiki, rfc_core as rfc, textclean
sys.path.insert(0, str(R / "tests")); from test_eve import unl

HIDDEN = ["\U000e0041", "\U000e0001", "\ufe0f", "\U000e0100", "\u2028", "\u2029", "\u034f", "\u061c", "\u180e", "\u3164", "\u200b", "\u202e", "\u2066", "\ufeff", "\u00ad", "\x1b", "\x07", "\u2063", "\ufffa"]


class Hidden(unittest.TestCase):
    def test_textclean_removes_all_but_keeps_text_tab_newline(self):
        raw = "A" + "".join(HIDDEN) + "B\tC\nD"
        self.assertEqual(textclean.strip_hidden(raw), "AB\tC\nD")
    def test_applied_in_every_core(self):
        raw = "x\U000e0041\U000e0042\U000e0043 CANARY\u2028y"
        self.assertEqual(wiki.clean(raw), "x CANARYy"); self.assertEqual(eve._s(raw), "x CANARYy"); self.assertEqual(rfc.strip_invisible(raw), "x CANARYy")
        self.assertEqual(rfc.clean(raw), ["x CANARYy"])
    def test_hidden_text_cannot_survive_in_eve_result(self):
        x = unl(["R1", "R2"], [("R1", "R2")]).replace('name="R1"', 'name="R1\U000e0049\U000e0047\U000e004e"', 1)
        self.assertEqual(json.dumps(eve.validate(x), ensure_ascii=True).count("\\udb40"), 0)


class EveFindings(unittest.TestCase):
    def test_ev1_parallel_links_are_not_a_single_link_spof(self):
        two = eve.validate(unl(["CORE1", "CORE2"], [("CORE1", "CORE2"), ("CORE1", "CORE2")]))
        self.assertFalse(any("SPOF links" in w for w in two["warnings"])); self.assertIn("No single-link SPOFs", two["passed"])
        one = eve.validate(unl(["CORE1", "CORE2"], [("CORE1", "CORE2")]))
        self.assertTrue(any("SPOF links" in w for w in one["warnings"]))
    def test_ev2_shared_segment_is_not_a_direct_forbidden_link(self):
        ifs = lambda n, i: f'<interface id="{i}" network_id="1"/>'
        nodes = "".join(f'<node id="{i}" name="{n}">{ifs(n, 0)}</node>' for i, n in enumerate(["CORE1", "HOST1", "DIST1", "CORE2"], 1))
        r = eve.validate(f'<lab name="m"><topology><nodes>{nodes}</nodes><networks><network id="1" name="mgmt" type="bridge"/></networks></topology></lab>')
        self.assertFalse(any("Forbidden adjacency" in f for f in r["failures"])); self.assertTrue(any("shares a multi-endpoint segment" in w for w in r["warnings"]))
        direct = eve.validate(unl(["HOST1", "CORE1"], [("HOST1", "CORE1")]))
        self.assertTrue(any("Forbidden adjacency (direct link)" in f for f in direct["failures"]))
    def test_ev3_message_explains_the_limit(self):
        nodes = "".join(f'<node id="{i}" name="N{i}"><interface id="0" network_id="1"/></node>' for i in range(eve.MAX_NET_MEMBERS + 1))
        with self.assertRaises(eve.UnlError) as c: eve.validate(f'<lab>{nodes}<network id="1"/></lab>')
        self.assertIn("split the segment", str(c.exception))
    def test_ev4_duplicate_ids_rejected(self):
        with self.assertRaises(eve.UnlError): eve.validate('<lab><node id="1" name="A"><interface id="0" network_id="1"/></node><node id="1" name="B"><interface id="0" network_id="1"/></node><network id="1"/></lab>')
        with self.assertRaises(eve.UnlError): eve.validate('<lab><node id="1" name="A"/><node id="1\u200b" name="B"/></lab>')
        with self.assertRaises(eve.UnlError): eve.validate('<lab><node id="1" name="A"/><network id="1"/><network id="1"/></lab>')
    def test_e1_partition_report_is_deterministic(self):
        x = unl(["R1", "R2", "R3", "R4", "R5", "R6"], [("R1", "R2"), ("R3", "R4"), ("R5", "R6")])
        first = [f for f in eve.validate(x)["failures"] if "partitioned" in f][0]
        self.assertEqual(first, [f for f in eve.validate(x)["failures"] if "partitioned" in f][0]); self.assertLess(first.index("R1"), first.index("R3"))


class Slow(unittest.TestCase):
    class Drip:
        headers = {"Content-Type": "application/json"}
        def read1(self, n): time.sleep(0.01); return b"x"
    def test_wk1_overall_deadline_wiki_and_rfc(self):
        for core, err in ((wiki, wiki.WikiError), (rfc, rfc.RfcError)):
            old = core.TIMEOUT; core.TIMEOUT = 0.05
            try:
                with self.assertRaises(err) as c: core._read(self.Drip(), 10**9)
                self.assertIn("overall timeout", str(c.exception))
            finally: core.TIMEOUT = old


class WikiShapes(unittest.TestCase):
    def setUp(self): wiki._cache.clear(); self._f = wiki._fetch
    def tearDown(self): wiki._fetch = self._f
    def test_wk3_malformed_api_shapes_become_wikierror(self):
        for body in ('{"query": []}', '{"query": {"pages": "x"}}', '{"query": {"pages": [1]}}', '{"query": {"pages": [{"title": "t", "ns": 0, "extlinks": 5}]}}', '{"query": {"search": [5]}}', '{"query": {"search": 3}}', "[]", "null", "5"):
            wiki._cache.clear(); wiki._fetch = lambda u, b=body: b
            for fn, a in ((wiki.summary, ("T",)), (wiki.references, ("T",)), (wiki.categories, ("T",)), (wiki.content, ("T",)), (wiki.search, ("t",))):
                try: fn(*a)
                except wiki.WikiError: pass
                except Exception as e: self.fail(f"{fn.__name__} on {body!r} raised {type(e).__name__}: {e}")
    def test_wk4_other_namespaces_refused(self):
        wiki._fetch = lambda u: json.dumps({"query": {"pages": [{"title": "User:Someone", "ns": 2, "extract": "attacker text"}]}})
        with self.assertRaises(wiki.WikiError) as c: wiki.summary("User:Someone")
        self.assertIn("namespaces", str(c.exception))


if __name__ == "__main__":
    unittest.main()


class RealDrip(unittest.TestCase):
    """H2-2 / WK-1b with a real socket: a server that sends one byte at a time must be cut at the overall deadline."""
    def test_real_http_drip_is_cut_off(self):
        import http.server, threading, urllib.request
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length", "100000"); self.end_headers()
                try:
                    for _ in range(40):
                        self.wfile.write(b"x"); self.wfile.flush(); time.sleep(0.2)
                except OSError: pass
            def log_message(self, *a): pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            for core, err in ((wiki, wiki.WikiError), (rfc, rfc.RfcError)):
                old = core.TIMEOUT; core.TIMEOUT = 1.0
                try:
                    r = urllib.request.urlopen(f"http://127.0.0.1:{srv.server_port}/", timeout=5); t = time.monotonic()
                    with self.assertRaises(err): core._read(r, 10**6)
                    self.assertLess(time.monotonic() - t, 2.5)
                finally: core.TIMEOUT = old
        finally: srv.shutdown(); srv.server_close()


class Review2(unittest.TestCase):
    def test_h2_3_head_regex_is_not_superlinear(self):
        line = "RFC 1" + " " * 4000 + "x" * 50
        t = time.monotonic(); rfc.clean(line + "\n" + "RFC 1" + " " * 2000 + "A" + " " * 2000 + "B"); self.assertLess(time.monotonic() - t, 0.5)
    def test_h2_3_real_page_header_still_removed(self):
        self.assertEqual(rfc.clean("RFC 4271              BGP-4              January 2006\nkeep"), ["keep"])
    def test_h2_4_search_strips_hidden(self):
        orig = rfc._cached; rfc._cached = lambda url, cap: "0001 A\u202ebad\U000e0041 title. (Format: TXT)\n\n"
        try:
            out = json.dumps(rfc.search("bad"), ensure_ascii=True)
            self.assertNotIn("202e", out.lower()); self.assertNotIn("udb40", out.lower())
        finally: rfc._cached = orig
    def test_h2_6_surrogates_and_newlines(self):
        self.assertNotIn("\ud800", textclean.strip_hidden("a\ud800b")); self.assertEqual(eve._s("A\nFAIL: x"), "A FAIL: x")
    def test_h2_5_deep_json_is_a_clean_error(self):
        with self.assertRaises(eve.UnlError): eve.validate(unl(["A", "B"], [("A", "B")]), "[" * 100000)
    def test_h2_1_xml_declarations_blocked_in_proxy(self):
        sys.path.insert(0, str(R / "mcp" / "_shared")); import proxy
        for x in ('<!DOC<!DOCTYPE x>TYPE r [<!ENTITY a "b">]>', "<!doctype a>", "<! ENTITY x 'y'>", "<!Element e>"):
            self.assertTrue(proxy.has_xml_decl({"ruleset_payload": x}), x)
        self.assertTrue(proxy.has_xml_decl({"a": [{"b": "<!DOCTYPE z>"}]}))
        self.assertFalse(proxy.has_xml_decl({"ruleset_payload": "<config><rule/></config>", "vendor": "paloalto"}))
        a = json.loads((R / "mcp" / "servers.json").read_text())["fwrule"]["args"]
        self.assertIn("--reject-xml-declarations", a)
        cap = [x for x in a if x.startswith("FOMC_MAX_RULESET_BYTES=")][0]; self.assertLessEqual(int(cap.split("=")[1]), 64 * 1024 * 1024)


class Px7AndE3(unittest.TestCase):
    def test_px7_edited_cache_with_recomputed_hash_is_refused_when_pinned(self):
        import subprocess, tempfile
        sys.path.insert(0, str(R / "mcp" / "_shared")); import proxy
        P = R / "mcp" / "_shared" / "proxy.py"
        good = json.loads((R / "mcp" / "fwrule" / "tools.cache.json").read_text())
        pin = good["sha256"]
        evil = json.loads(json.dumps(good)); evil["tools"][0].setdefault("annotations", {})["readOnlyHint"] = False
        evil["sha256"] = proxy.tools_hash(evil["tools"])              # attacker recomputes the self-check
        with tempfile.TemporaryDirectory() as t:
            f = pathlib.Path(t) / "c.json"; f.write_text(json.dumps(evil))
            run = lambda extra: subprocess.run([sys.executable, str(P), *extra, "--cache", str(f), "--", "true"], capture_output=True, text=True, input="", timeout=20)
            unpinned = run([]); self.assertEqual(unpinned.returncode, 0)             # old behaviour: starts (this is the PX-7 gap)
            pinned = run(["--expect-sha256", pin]); self.assertNotEqual(pinned.returncode, 0)
            self.assertIn("pinned --expect-sha256", pinned.stderr)
            f.write_text(json.dumps(good)); self.assertEqual(run(["--expect-sha256", pin]).returncode, 0)
            self.assertNotEqual(run(["--expect-sha256", "0" * 64]).returncode, 0)

    def test_px7_registry_pin_matches_cache_and_lint_checks_it(self):
        reg = json.loads((R / "mcp" / "servers.json").read_text())["fwrule"]["args"]
        cache = json.loads((R / "mcp" / "fwrule" / "tools.cache.json").read_text())
        self.assertEqual(reg[reg.index("--expect-sha256") + 1], cache["sha256"])
        import re
        self.assertIn("--expect-sha256", (R / "scripts" / "lint.py").read_text())

    def test_e3_interface_caps_are_errors_not_truncation(self):
        many = "".join(f'<interface id="{i}" network_id="1"/>' for i in range(eve.MAX_IFACES_PER_NODE + 1))
        with self.assertRaises(eve.UnlError) as c: eve.validate(f'<lab><topology><nodes><node id="1" name="A">{many}</node></nodes><networks><network id="1"/></networks></topology></lab>')
        self.assertIn("interfaces (limit", str(c.exception))
        old = eve.MAX_LINKS; eve.MAX_LINKS = 5
        try:
            nodes = "".join(f'<node id="{i}" name="N{i}"><interface id="0" network_id="1"/><interface id="1" network_id="1"/></node>' for i in range(1, 5))
            with self.assertRaises(eve.UnlError) as c: eve.validate(f'<lab><topology><nodes>{nodes}</nodes><networks><network id="1"/></networks></topology></lab>')
            self.assertIn("interfaces in the lab", str(c.exception))
        finally: eve.MAX_LINKS = old


class SharedProxy(unittest.TestCase):
    def test_every_server_goes_through_the_proxy_with_a_pin(self):
        reg = json.loads((R / "mcp" / "servers.json").read_text())
        for n, e in reg.items():
            a = e["args"]
            self.assertEqual(e["command"], "python3", n); self.assertEqual(a[0], "{root}/mcp/_shared/proxy.py", n)
            cache = json.loads((R / "mcp" / n / "tools.cache.json").read_text())
            self.assertEqual(a[a.index("--expect-sha256") + 1], cache["sha256"], n)
            self.assertEqual(a[a.index("--cache") + 1], f"{{root}}/mcp/{n}/tools.cache.json", n)
        flagged = [n for n, e in reg.items() if "--reject-xml-declarations" in e["args"]]
        self.assertEqual(flagged, ["fwrule"])      # the XML guard is fwrule-specific; other servers must not reject '<!DOCTYPE' text

    def test_xml_guard_is_opt_in(self):
        import subprocess, tempfile
        P = R / "mcp" / "_shared" / "proxy.py"
        cache = R / "mcp" / "wikipedia" / "tools.cache.json"
        fake = "import json,sys\nfor l in sys.stdin:\n m=json.loads(l)\n if m.get('method')=='tools/call': print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'content':[{'type':'text','text':'forwarded'}]}}),flush=True)\n elif m.get('method')=='initialize': print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'protocolVersion':'2025-03-26','capabilities':{},'serverInfo':{'name':'f','version':'0'}}}),flush=True)\n elif m.get('method')=='tools/list': print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'tools':json.load(open(sys.argv[1]))['tools']}}),flush=True)\n"
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_summary", "arguments": {"page": "<!DOCTYPE html>"}}}]
        with tempfile.TemporaryDirectory() as t:
            f = pathlib.Path(t) / "c.py"; f.write_text(fake)
            def run(extra):
                p = subprocess.run([sys.executable, str(P), *extra, "--cache", str(cache), "--", sys.executable, str(f), str(cache)], input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True, timeout=30)
                return {json.loads(l)["id"]: json.loads(l) for l in p.stdout.splitlines()}
            self.assertIn("forwarded", json.dumps(run([])[2]))
            self.assertEqual(run(["--reject-xml-declarations"])[2]["error"]["code"], -32602)

    def test_bad_options_are_refused(self):
        import subprocess
        P = R / "mcp" / "_shared" / "proxy.py"
        for opts in (["--set-env", "lowercase=1"], ["--set-env", "A"], ["--bogus"], ["--cache"]):
            r = subprocess.run([sys.executable, str(P), *opts, "--", "true"], capture_output=True, text=True, input="", timeout=20)
            self.assertNotEqual(r.returncode, 0, opts)


class MalformedHttp(unittest.TestCase):
    """Tester W-5/B-1: a peer that does not speak HTTP must give the module's own error, not a raw http.client exception."""
    def test_wiki_and_rfc(self):
        import http.client
        sys.path.insert(0, str(R / "mcp" / "wikipedia")); sys.path.insert(0, str(R / "mcp" / "rfc-lookup"))
        import wiki_core, rfc_core
        class Op:
            def __init__(s, exc): s.exc = exc
            def open(s, *a, **k): raise s.exc
        for mod, err, call in ((wiki_core, wiki_core.WikiError, lambda: wiki_core._fetch(wiki_core.API + "?x=1")),
                               (rfc_core, rfc_core.RfcError, lambda: rfc_core._fetch("https://www.rfc-editor.org/rfc/rfc1.txt", 1000))):
            orig = mod.urllib.request.build_opener
            try:
                for exc in (http.client.BadStatusLine("x"), http.client.IncompleteRead(b""), ConnectionResetError()):
                    mod.urllib.request.build_opener = lambda *a, e=exc: Op(e)
                    with self.assertRaises(err, msg=(mod.__name__, exc)): call()
            finally: mod.urllib.request.build_opener = orig


class ProxyDeepJson(unittest.TestCase):
    def test_h5_2_deeply_nested_line_does_not_kill_the_proxy(self):
        import subprocess
        P = R / "mcp" / "_shared" / "proxy.py"; cache = R / "mcp" / "wikipedia" / "tools.cache.json"
        deep = "[" * 100000 + "]" * 100000
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}
        lst = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        p = subprocess.run([sys.executable, str(P), "--cache", str(cache), "--", "true"], input=deep + "\n" + json.dumps(init) + "\n" + json.dumps(lst) + "\n", capture_output=True, text=True, timeout=30)
        out = [json.loads(l) for l in p.stdout.splitlines()]
        self.assertIn(out[0]["error"]["code"], (-32700, -32600)); self.assertEqual(out[-1]["id"], 2)   # parse error or invalid request depending on the json recursion limit of this Python; self.assertIn("tools", out[-1]["result"])


class Review5Deferred(unittest.TestCase):
    def test_h5_3_notifications_do_not_extend_a_call(self):
        import subprocess, time as _t
        P = R / "mcp" / "_shared" / "proxy.py"; cache = R / "mcp" / "wikipedia" / "tools.cache.json"
        chatty = ("import json,sys,time\n"
                  "for l in sys.stdin:\n"
                  " m=json.loads(l)\n"
                  " if m.get('method')=='initialize': print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'protocolVersion':'2025-03-26','capabilities':{},'serverInfo':{'name':'c','version':'0'}}}),flush=True)\n"
                  " elif m.get('method')=='tools/list': print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'tools':json.load(open(sys.argv[1]))['tools']}}),flush=True)\n"
                  " elif m.get('method')=='tools/call':\n"
                  "  while True: print(json.dumps({'jsonrpc':'2.0','method':'notifications/progress','params':{}}),flush=True); time.sleep(0.2)\n")
        import tempfile, os
        with tempfile.TemporaryDirectory() as t:
            f = pathlib.Path(t) / "c.py"; f.write_text(chatty)
            msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_summary", "arguments": {"page": "OSPF"}}}]
            env = dict(os.environ, NETPAW_PROXY_CALL_TIMEOUT="2")
            t0 = _t.monotonic()
            p = subprocess.run([sys.executable, str(P), "--cache", str(cache), "--", sys.executable, str(f), str(cache)], input="\n".join(json.dumps(m) for m in msgs) + "\n",
                               capture_output=True, text=True, timeout=40, env=env)
            out = {json.loads(l)["id"]: json.loads(l) for l in p.stdout.splitlines() if '"id"' in l}
            self.assertIn("error", out[2]); self.assertIn("did not answer", json.dumps(out[2])); self.assertLess(_t.monotonic() - t0, 20)

    def test_h5_4_deadline_covers_slow_headers(self):
        import socket, threading, time as _t
        sys.path.insert(0, str(R / "mcp" / "_shared")); import netguard
        def slow(): _t.sleep(5); return "late"
        t0 = _t.monotonic()
        with self.assertRaises(TimeoutError): netguard.with_deadline(slow, 0.5, TimeoutError("x"))
        self.assertLess(_t.monotonic() - t0, 2)
        self.assertEqual(netguard.with_deadline(lambda: 7, 1, TimeoutError()), 7)
        with self.assertRaises(KeyError): netguard.with_deadline(lambda: {}["x"], 1, TimeoutError())
        # real dripping peer against urllib through wiki_core's opener path (status line one byte every 0.3 s)
        sys.path.insert(0, str(R / "mcp" / "wikipedia")); import wiki_core
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
        def drip():
            c, _ = srv.accept()
            try:
                for ch in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n":
                    c.send(bytes([ch])); _t.sleep(0.3)
            except OSError: pass
            finally: c.close()
        threading.Thread(target=drip, daemon=True).start()
        old = (wiki_core.TIMEOUT,); wiki_core.TIMEOUT = 1
        try:
            t0 = _t.monotonic()
            with self.assertRaises(wiki_core.WikiError):
                wiki_core.with_deadline(lambda: wiki_core.urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=wiki_core.TIMEOUT).read(), wiki_core.TIMEOUT + 1, wiki_core.WikiError("slow"))
            self.assertLess(_t.monotonic() - t0, 5)
        finally: wiki_core.TIMEOUT = old[0]; srv.close()

    def test_h5_6_cache_is_bounded_by_size(self):
        sys.path.insert(0, str(R / "mcp" / "_shared")); import netguard
        c = {}
        for i in range(10):
            netguard.trim(c, 64, 1000 - 300); c[i] = "x" * 300
        self.assertLessEqual(sum(map(len, c.values())), 1000); self.assertEqual(list(c)[-1], 9)
        sys.path.insert(0, str(R / "mcp" / "bgp-intel")); import bgp_core
        self.assertLessEqual(bgp_core.CACHE_CHARS, 32_000_000)
