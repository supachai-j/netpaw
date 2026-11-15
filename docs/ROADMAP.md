# Roadmap (next steps, ordered; evidence before claims)

Status 2026-11-15: 6 skills (subnet-calculator, fwrule-analyzer, rfc-lookup, eve-lab-topology-design, wikipedia-research, bgp-registry-intel), all `experimental`. PRs #6-#13 merged; repository renamed to netpaw (D-12). Still open: the items below. The user-facing summary is docs/manual/roadmap.md.

## R1 - close rfc-lookup (this week)
- [x] cross-review findings R6-1..R6-4, RL-1 (invisible/control chars stripped), RL-2 (cache cap), RL-3 (8-word limit enforced)
- [x] real-model injection test (reviewer ran 6 variants x 2 runs: no compliance; text-tampering variant is only stopped by TLS + host pin)
- [x] #6 and #7 merged
- [ ] tag v0.2.0 pre-release

## R2 - make skills measurably useful (before adding more)
- [ ] trigger eval 3 runs/query on all skills; target validation >= 80% and 0 false positives
- [ ] output eval with vs without skill (evals.json) for subnet-calculator first; if it does not beat baseline on hard cases, drop the "accuracy" claim and keep it as a deterministic checker only
- [ ] Codex cold-start: proxy pattern (as fwrule) for rfc-lookup and subnet-calc if still hidden at first start

## R3 - runtimes
- [ ] re-test PR #7 content on Codex, thClaws, OpenClaw (mock model, no credentials) after merge
- [ ] real-model run per runtime: owner logs in on a worker (Rule 30)
- [ ] `.agents/skills` target: test or remove

## R4 - next skills (each: own review note, egress declared, offline fixtures, evals, scan, cross-review)
1. eve-lab-topology-design + offline .unl validator (done, D-10), wikipedia-research (done, D-11)
2. bgp-registry-intel (done as experimental, D-14; 7 of the upstream 10 tools; resource_report and atlas_* deferred; pending tester run, scanners and security review)
3. network-data-analysis (PDPA risk: synthetic data only)
Not before a server-side write gate exists: anything with `risk: write`, pyATS, vendor controllers, chat integrations.

## R5 - project hygiene
- [ ] B-3: MCP config points at a stable install dir, not a checkout
- [x] PX-7: the proxy takes `--expect-sha256` pinned in mcp/servers.json (lint compares it with the cache); CODEOWNERS already covers /mcp/
- [ ] fuzz the fwrule XML parser
- [x] H5-3 proxy call timeout per call; H5-4 wall-clock deadline including connect, status line and headers (mcp/_shared/netguard.py); H5-6 caches bounded by total characters as well as entries
- [x] H5-7 langpolicy scans the TypeScript dist/ output, treats dynamic import/require of a non-literal as code evaluation, and covers Go net/smtp, net/textproto, x/sys/unix, plugin and Rust libc exec/fork/system (still a regex tripwire)
- [ ] add Cisco Skill Scanner (and SkillSpector after vetting its maintainers) as a scheduled CI job on a pinned version
- [ ] update docs/CONFORMANCE.md SHAs after the history rewrite
- Owner-only: PyPI/npm name reservation, GitHub Support request, tailnet serve of the manual
