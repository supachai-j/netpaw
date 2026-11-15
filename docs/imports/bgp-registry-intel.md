# bgp-registry-intel - review note (NOT an import: independent reimplementation)
Upstream: NetClaw skill `bgp-registry-intel` (134 lines, Apache-2.0, NetClaw @cfafa46c). Read 2026-11-15: SKILL.md only. It calls `bgp-intel-mcp` through `$BGP_INTEL_MCP_CMD`. That server's source is in NetClaw at `mcp-servers/bgp-intel-mcp/` (10 Python files; the tester ran it as a control against the acceptance pack: 32 of 71 tests passed). I did not read it while writing ours and nothing of it was copied, so the attribution covers the skill idea, tool names and interpretation rules only.
- VERIFIED (upstream text): 10 tool names; credentials none; read-only; rules about RPKI states, registry versus routing, PeeringDB being self-reported.
- VERIFIED (scanner, earlier NetClaw-wide run by the tester): SkillSpector 2.8.2 scored the upstream SKILL.md 0/100 SAFE. Our own files have not been scanned yet.
Decision (D-14): own stdlib server with 7 tools; skill text rewritten, keeping the interpretation rules.

## Sources (checked live 2026-11-15 from the control host)
| Source | Endpoint | Used for |
|---|---|---|
| RIPE NCC RPKI validator | `rpki-validator.ripe.net/api/v1/validity/AS<n>/<prefix>` | rpki_validate |
| RIPEstat | `stat.ripe.net/data/{as-overview,announced-prefixes}/data.json` | routing_* |
| IANA RDAP bootstrap | `data.iana.org/rdap/{ipv4,ipv6,asn}.json` | choose the RIR |
| RDAP | `rdap.db.ripe.net`, `rdap.arin.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net` (`ip/`, `autnum/` only) | registry_* |
| PeeringDB | `www.peeringdb.com/api/net?asn=` | peering_* |
Observed: the four RPKI outcomes (valid; invalid with a different AS; invalid with a too-specific prefix; not-found) on RIPE NCC's own prefix; RDAP answers from all five RIRs; an HTTP 307 from LACNIC to `rdap.registro.br` (not followed, reported); one HTTP 502 from the validator on the first IPv6 request, 200 when repeated by hand; PeeringDB returns HTTP 404 for an ASN with no record (mapped to `no_record`).

## Controls
Host and path allow-list checked before every request and on every referral; https only; no userinfo, port, fragment, `..` or percent-encoding in the path; redirects refused except RIR-to-RIR RDAP referrals (2 hops); JSON content types only; 15 s overall deadline; 8 MB cap; serial, 0.25 s per host; inputs parsed with `ipaddress` and a strict ASN pattern; private, reserved and documentation resources refused locally; all returned strings flattened, stripped of hidden characters and capped; personal data dropped (organisation vCards and abuse-role mailboxes only; PeeringDB `poc` never requested); results marked untrusted with source, URL, time and cache age; no files written; no credentials.

## Found while testing
`ipaddress.ip_network("0.0.0.0/0").is_global` is true, so a default route passed the first private-space check. Fixed by also checking both ends of the range and a minimum length (/8 for IPv4, /16 for IPv6); test in tests/test_bgp.py.

## NOT checked
Behaviour when a source rate limits (a 429 becomes an error; no retry); PeeringDB anonymous query limits; terms of use of each source for automated use (read them before heavy use; the skill forbids sweeps); whether an abuse mailbox can be a personal address at small holders (possible; it is still the published abuse contact); HTTPS_PROXY environments; any agent runtime; any real model; scanners; independent security review.

## Tester findings on PR #18 (H4, commit 23c44d1) and fixes
Acceptance pack by the tester (73 tests, written before seeing the code): 9 failed on 23c44d1. After the fixes below, 73 pass (1 skipped: optional tools not built); the same pack against 23c44d1's core still fails 17 records, so the pack detects the gaps.
- B-1 a non-HTTP peer leaked `http.client` exceptions: now `source unavailable: malformed HTTP response`. Same fix in wikipedia and rfc-lookup (W-5).
- B-2 PeeringDB anonymous limit is 20 requests/minute: at least 3.1 s between PeeringDB requests.
- B-3 PeeringDB `website` could carry `javascript:`: only http(s) URLs with a host are returned.
- B-4 after an RDAP referral, `source` is the registry that answered and `referred_from` the one asked.
- B-5 IPv6 forms carrying a private IPv4 (NAT64 64:ff9b::/96 and 64:ff9b:1::/48, IPv4-mapped/compatible, 6to4, Teredo) are refused locally.
- B-6 an RPKI answer about a different prefix or AS than asked is `validation_unavailable`.
- B-7 RIPEstat requests carry `sourceapp=netpaw` as RIPE asks.
- Docs D-1..D-4 (tester part 2): SKILL.md now names the embedded-IPv4 refusal and the supernet limit; this note names the upstream server's location; the manual says PeeringDB contacts are "not returned" rather than "not requested"; pacing text matches the code.
- Tester part 2 on 23c44d1: Codex first session listed all 6 servers in 6/6 fresh homes; thClaws and OpenClaw called rpki_validate; Cisco skill-scanner 0 findings and SkillSpector 0/100 on the skill folder; server-code findings were the declared registry calls.

## Security review H5 (reviewer, commit 59b0997): blocks merge = no
Fixed in this PR:
- H5-1 PDPA wording was stronger than the code. Now: abuse mailboxes of `kind: individual` entities are withheld (the caveat says how many); phone-like digit runs (8+ digits, not dates or IPv4) in free text are masked; docs say plainly that free-text names can still contain a person's name.
- H5-2 the shared proxy exited on one deeply nested JSON line (RecursionError). Now a parse error; the proxy keeps serving. Test: tests/test_hardening.py ProxyDeepJson.
- H5-5 "Honors HTTPS_PROXY" was false behind the shared proxy (env allow-list). Docs of bgp-registry-intel, rfc-lookup and wikipedia-research now say the server connects directly; the proxy comment about overriding FOMC_* is corrected.
- H5-8 a query overlapping special-purpose space (IANA registries, plus deprecated site-local fec0::/10) is refused, so 172.0.0.0/8, 100.0.0.0/8, 198.0.0.0/8, 64:ff9b::/32 and fec0::1 no longer leave the host.
- H2-6 residue: the 29 remaining Unicode Cf characters are now stripped by textclean (0 Cf characters left unstripped).
Deferred (ROADMAP R5): H5-3 proxy timeout per call not per line; H5-4 deadline also for status line and headers; H5-6 cache memory bound by bytes; H5-7 langpolicy must scan dist/ and catch dynamic imports, net/smtp, x/sys/unix before the first non-Python server.
