# netpaw 0.2.0 (pre-release)

All skills remain `experimental`. Evidence for each claim is in the linked PRs and review notes.

## New
- Six skills: subnet-calculator, fwrule-analyzer, rfc-lookup, eve-lab-topology-design, wikipedia-research (#11), bgp-registry-intel (#18).
- bgp-registry-intel: RPKI origin validation, RDAP registration and abuse mailbox, RIPE RIS announced prefixes, PeeringDB. Nine public hosts with a host+path allow-list; private and special-purpose space refused locally; personal contact records dropped.
- Project renamed to netpaw (D-12); English manual, Thai summary (#13, #14).
- Language policy D-13: Python default, Go second, TypeScript/Rust closed; deny-by-default lint for non-Python servers (#15).

## Changed
- Every MCP server starts behind a shared lazy proxy that answers from a hash-pinned tool cache (#16, #17). In the tester's runs Codex then listed all servers in the first session (6/6 and 12/12 fresh homes); before, only one server was visible in the first four sessions.

## Security
- Reviews: tester cross-reviews (H1, H3, H4) and independent security reviews (H2, H5); none blocked a merge.
- Fixed: proxy tool-definition hash pin (PX-7), eve-lab interface caps (E-3), XML declaration rejection and ruleset cap for fwrule (H2-1), overall read deadlines (H2-2, H5-4), bounded regex (H2-3), hidden-character stripping incl. all Unicode Cf (H2-4, H2-6), deep-JSON resilience (H2-5, H5-2), per-call proxy deadline (H5-3), size-bounded caches (H5-6), PDPA filtering in bgp-intel (H5-1), special-purpose space refusal (H5-8), malformed HTTP handling (B-1/W-5).
- Open: H5-7 (langpolicy gaps; must close before the first non-Python server). The fwrule upstream parser issue H2-1 is mitigated in our proxy, not fixed upstream.

## Not verified
Real models on Codex, thClaws, OpenClaw and Hermes (mock model only); Windows and macOS; Claude Code marketplace install; real EVE-NG `.unl` files; trigger evaluation with 3 runs per query; output evaluation with versus without skills.
