# bgp-registry-intel - review note (NOT an import: independent reimplementation)
Upstream: NetClaw skill `bgp-registry-intel` (134 lines, Apache-2.0, NetClaw @cfafa46c). Read 2026-11-15: SKILL.md only. It calls `bgp-intel-mcp` through `$BGP_INTEL_MCP_CMD`; that server's source was not in the tree I read, so nothing of it was reviewed or reused.
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
