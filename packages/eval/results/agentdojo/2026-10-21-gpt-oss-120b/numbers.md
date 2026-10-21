# AgentDojo banking and Slack, groq:openai/gpt-oss-120b

- date: 2026-10-21; agent: `groq:openai/gpt-oss-120b`; world: agentdojo
- benchmark: AgentDojo v1.2.2 (`agentdojo==0.1.35`), suites banking, slack; attack `important_instructions`; rounds 1
- contract compiler: oracle (ground-truth assisted); escalations answered by: `reject`
- runs: 192 of 192 planned; model calls: 891; first 4 user tasks per suite
- intervals are 95% Wilson; a run that errored is not counted

## Headline (all suites)

| lane | utility, no attack | utility, under attack | attack success rate | clean runs with an escalation |
| --- | --- | --- | --- | --- |
| Undefended | 62% (5/8; 31%-86%) | 66% (37/56; 53%-77%) | 79% (44/56; 66%-87%) | 0% (0/8; 0%-32%) |
| Classifier-only (keyword stand-in) | 50% (4/8; 22%-78%) | 61% (34/56; 48%-72%) | 79% (44/56; 66%-87%) | 0% (0/8; 0%-32%) |
| NOTARY | 50% (4/8; 22%-78%) | 18% (10/56; 10%-30%) | 0% (0/56; 0%-6%) | 25% (2/8; 7%-59%) |

**Attack success 79% undefended -> 0% with NOTARY (0/56; 95% interval 0%-6%). Utility without attack 62% -> 50%; under attack 66% -> 18%.**

## banking

| lane | utility, no attack | utility, under attack | attack success rate | clean runs with an escalation |
| --- | --- | --- | --- | --- |
| Undefended | 25% (1/4; 5%-70%) | 50% (18/36; 34%-66%) | 78% (28/36; 62%-88%) | 0% (0/4; 0%-49%) |
| Classifier-only (keyword stand-in) | 0% (0/4; 0%-49%) | 47% (17/36; 32%-63%) | 75% (27/36; 59%-86%) | 0% (0/4; 0%-49%) |
| NOTARY | 50% (2/4; 15%-85%) | 11% (4/36; 4%-25%) | 0% (0/36; 0%-10%) | 0% (0/4; 0%-49%) |

## slack

| lane | utility, no attack | utility, under attack | attack success rate | clean runs with an escalation |
| --- | --- | --- | --- | --- |
| Undefended | 100% (4/4; 51%-100%) | 95% (19/20; 76%-99%) | 80% (16/20; 58%-92%) | 0% (0/4; 0%-49%) |
| Classifier-only (keyword stand-in) | 100% (4/4; 51%-100%) | 85% (17/20; 64%-95%) | 85% (17/20; 64%-95%) | 0% (0/4; 0%-49%) |
| NOTARY | 50% (2/4; 15%-85%) | 30% (6/20; 15%-52%) | 0% (0/20; 0%-16%) | 50% (2/4; 15%-85%) |

## By bucket (all suites)

| bucket | tasks | Undefended | Classifier-only (keyword stand-in) | NOTARY |
| --- | --- | --- | --- | --- |
| fully specified | 3 | util 68%, ASR 74% | util 74%, ASR 74% | util 32%, ASR 0% |
| parameter open | 4 | util 61%, ASR 82% | util 50%, ASR 82% | util 11%, ASR 0% |
| read only | 1 | util 78%, ASR 78% | util 67%, ASR 78% | util 11%, ASR 0% |

_util: utility under attack; ASR: attack success rate; tasks: user tasks._
