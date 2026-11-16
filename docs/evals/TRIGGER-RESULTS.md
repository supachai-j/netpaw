# Trigger eval results (Claude Code adapter, `scripts/eval_triggers.py`)

Method (agentskills.io "Optimizing skill descriptions"): 20 queries per skill (10 should / 10 should-not trigger, split train 12 / validation 8), 1 run per query, `claude -p` with this repo as plugin, tools restricted to Skill + this plugin's MCP tools. A query "triggers" if the Skill tool names the skill or one of its MCP tools is called. Pass = trigger rate > 0.5 for should-trigger, <= 0.5 for should-not.

Limits: ONE run per query (noisy; the guide recommends 3), one model, one runtime. Treat as a signal, not proof. Output-quality evals (`evals/evals.json`, with/without skill) are written but NOT yet run.

| skill | description version | train | validation |
|---|---|---|---|
| subnet-calculator | with "Use this skill when" + keywords | 6/12 | 4/8 |
| subnet-calculator | + "do not answer from memory" sentence | 7/12 | 5/8 |
| rfc-lookup | with "Use this skill when" + keywords | 8/12 | 4/8 |
| rfc-lookup | + "quote, do not recall" sentence | 11/12 | 8/8 |
| fwrule-analyzer | with "Use this skill when" + keywords | 9/12 | 5/8 |

Findings
- Every miss is a should-trigger query that the model answered from memory. No should-not query triggered a skill (false positives: 0).
- rfc-lookup improved clearly after naming the failure mode in the description; subnet-calculator barely did. The model is confident at subnet arithmetic, so a description alone may not be enough. Next options: tell the model (in the description) which exact outputs must come from the tool, test with 3 runs, then compare answer correctness with and without the skill (evals.json) before deciding the skill is worth its tokens.
- A first run scored ~0 because of a bug in the harness (tool-name match); fixed in the same change. Numbers above come from the fixed harness.
- The earlier all-zero baseline is discarded.

- Subnet-calculator and rfc-lookup trigger numbers vary by about 2 queries between identical runs (rfc-lookup train/validation 11/12 and 8/8 in one run, 12/12 and 6/8 in the next); read them as ranges.
| eve-lab-topology-design | "Use this skill when" description | 10/12 | 8/8 |

The 2 train misses are queries that mention a .unl file but contain no actual content, so the model asked for the file instead of calling the tool; they are weak queries, not necessarily a description problem. 1 run per query.
| wikipedia-research | "Use this skill when" description | 8/12 | 4/8 |
| wikipedia-research | + "always when they name Wikipedia or ask for sources" | 7/12 | 6/8 |

wikipedia-research stays weak: general background questions are answered from memory (0 false positives). Even some prompts that name Wikipedia did not call the tool in a single run; not investigated further. The skill may add little for well-known protocols; its value is citable, fetched sources, which the output eval must show before any claim beyond "experimental".
| bgp-registry-intel | "Use this skill when" description (commit 0a50384) | 12/12 | 8/8 |

bgp-registry-intel: 1 run per query, so read it as a range (other skills moved by about 2 queries between identical runs). All 10 should-not-trigger queries passed, including near misses (BGP theory, RFC 6811 text, RPKI history, router BGP neighbors). The queries name concrete prefixes and AS numbers, which makes them easier than real prompts; the "tested" level still needs 3 runs per query.

## 3 runs per query, all six skills (commit 34f371f, 2026-11-16)

Claude Code `claude -p`, 3 runs per query, a query passes when the trigger rate is above 0.5 in the expected direction. This is the run the `tested` level asks for (validation >= 80% and no false positive).

| skill | train | validation | false positives | trigger bar for tested |
|---|---|---|---|---|
| rfc-lookup | 12/12 | 8/8 | 0 | met |
| bgp-registry-intel | 12/12 | 8/8 | 0 | met (3 of 60 runs errored, counted as no data) |
| subnet-calculator | 10/12 | 8/8 | 0 | met |
| eve-lab-topology-design | 10/12 | 7/8 | 0 | met |
| fwrule-analyzer | 8/12 | 5/8 | 0 | not met |
| wikipedia-research | 11/12 | 6/8 | 1 ("what is the latest Cisco IOS XE release", 3/3 runs) | not met |

- Meeting the trigger bar does not make a skill `tested`: runtime checks on every claimed agent and a prompt-injection case with a real model are still required.
- Harness bug found and fixed in this change: a run that ended in an error (for example a usage limit) was counted as "did not trigger". In the first pass wikipedia-research and bgp-registry-intel, which ran last, scored 0/60 runs; a manual run of the same query triggered correctly. Those two skills were re-run with the fixed harness (numbers above). The other four come from the first pass, so any errored run there was counted as a miss: their numbers are a lower bound.
- fwrule-analyzer misses are queries that describe a ruleset without pasting a parsable one ("here are the existing rules", "these two JunOS policies"); the model asks for the rules or reasons in prose. wikipedia-research still answers well-known background from memory, and the description's "latest release" wording appears to pull in a vendor-release question it should leave alone.
- Cost: about 480 `claude -p` calls (360 first pass + 120 re-run), approved by the owner.
