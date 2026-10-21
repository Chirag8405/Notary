# SAMPLE: AgentDojo banking and Slack, scripted agent

> **SAMPLE, NOT A RESULT.** A scripted agent (no model) ran against the offline
> snapshot. It checks the harness and shows the shape of the output. Do not quote
> these numbers anywhere.

- date: 2026-10-21; agent: a scripted agent (no model); world: snapshot
- benchmark: AgentDojo v1.2.2 (`agentdojo==0.1.35`), suites banking, slack; attack `important_instructions`; rounds 1
- contract compiler: oracle (ground-truth assisted); escalations answered by: `reject`
- runs: 858 of 858 planned; model calls: 0
- intervals are 95% Wilson; a run that errored is not counted
- Scripted agent: utility and attack success are judged on the ground-truth calls.

## Headline (all suites)

| lane | utility, no attack | utility, under attack | attack success rate | clean runs with an escalation |
| --- | --- | --- | --- | --- |
| Undefended | 100% (37/37; 91%-100%) | 100% (249/249; 98%-100%) | 100% (249/249; 98%-100%) | 0% (0/37; 0%-9%) |
| Classifier-only (keyword stand-in) | 100% (37/37; 91%-100%) | 100% (249/249; 98%-100%) | 100% (249/249; 98%-100%) | 0% (0/37; 0%-9%) |
| NOTARY | 68% (25/37; 51%-80%) | 73% (181/249; 67%-78%) | 0% (0/249; 0%-2%) | 32% (12/37; 20%-49%) |

**SAMPLE (scripted agent): Attack success 100% undefended -> 0% with NOTARY (0/249; 95% interval 0%-2%). Utility without attack 100% -> 68%; under attack 100% -> 73%.**

## banking

| lane | utility, no attack | utility, under attack | attack success rate | clean runs with an escalation |
| --- | --- | --- | --- | --- |
| Undefended | 100% (16/16; 81%-100%) | 100% (144/144; 97%-100%) | 100% (144/144; 97%-100%) | 0% (0/16; 0%-19%) |
| Classifier-only (keyword stand-in) | 100% (16/16; 81%-100%) | 100% (144/144; 97%-100%) | 100% (144/144; 97%-100%) | 0% (0/16; 0%-19%) |
| NOTARY | 88% (14/16; 64%-97%) | 88% (126/144; 81%-92%) | 0% (0/144; 0%-3%) | 12% (2/16; 3%-36%) |

## slack

| lane | utility, no attack | utility, under attack | attack success rate | clean runs with an escalation |
| --- | --- | --- | --- | --- |
| Undefended | 100% (21/21; 85%-100%) | 100% (105/105; 96%-100%) | 100% (105/105; 96%-100%) | 0% (0/21; 0%-15%) |
| Classifier-only (keyword stand-in) | 100% (21/21; 85%-100%) | 100% (105/105; 96%-100%) | 100% (105/105; 96%-100%) | 0% (0/21; 0%-15%) |
| NOTARY | 52% (11/21; 32%-72%) | 52% (55/105; 43%-62%) | 0% (0/105; 0%-4%) | 48% (10/21; 28%-68%) |

## By bucket (all suites)

| bucket | tasks | Undefended | Classifier-only (keyword stand-in) | NOTARY |
| --- | --- | --- | --- | --- |
| fully specified | 8 | util 100%, ASR 100% | util 100%, ASR 100% | util 100%, ASR 0% |
| parameter open | 22 | util 100%, ASR 100% | util 100%, ASR 100% | util 52%, ASR 0% |
| action open | 3 | util 100%, ASR 100% | util 100%, ASR 100% | util 74%, ASR 0% |
| read only | 4 | util 100%, ASR 100% | util 100%, ASR 100% | util 100%, ASR 0% |

_util: utility under attack; ASR: attack success rate; tasks: user tasks._
