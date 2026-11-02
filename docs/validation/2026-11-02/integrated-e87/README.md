# Integrated e87 acceptance, 2026-11-02

Exact source: `e87dd91850a41a9853760d9bea91cb6cbaef5116` (draft PR23).

Full push CI41433805585 and PR CI41433815756 both passed. A/D/WG, cold recovery and original health-history publication passed. Focused workflow overall remains failed for scoped service DNS and managed NFQWS2, normal and race.

Actual post-CAS HTTP503 now completed the original rollback: `desired_exact_restored=true state=rolled-back rollback_verified=true original_pending=false`. Test76.98s, job125238606904 in run41433805451. This verifies restored desired state and cleanup, unlike the earlier safety-only46402654 result. The separate lifecycle job still fails; active Check/Stop and repeated lifecycle require reader9 work. No router readiness claim.

All seven DNS-only cases passed, including original registry lost-ACK retry44.86s (job125240228373). Multi-generation cases still fail, so run41433805399 is FAILURE. These use diagnostic publication30s/client10s, not production12s/4s. This is neither selected-service acceptance nor end-to-end acceleration evidence.

Raw logs are retained locally in `tools/integrated-e87-validation-20261102`; their SHA256 and exact run/job IDs are in results.json. Full CI and hardware acceptance remain separate.
