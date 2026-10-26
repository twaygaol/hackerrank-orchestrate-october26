# Evaluation Report

Generated: 2026-10-25T10:07:09+00:00

## Public sample evaluation

The agent is evaluated against all 32 public labeled examples in `dataset/sample_output.csv`. These are validation cases, not labels used by the prediction algorithm.

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | 32/32 (100.00%) |
| Exact row accuracy (status + complete ordered steps) | 18/32 (56.25%) |
| Sequence accuracy | 18/32 (56.25%) |
| Field accuracy (seven step fields, index-aligned; missing steps count as incorrect) | 1086/1351 (80.38%) |
| Step precision / recall / F1 (exact step signatures, order-independent) | 100.00% / 90.67% / 95.11% |

## Additional participant-created evaluation cases

| Case | Result | Purpose |
|---|---|---|
| custom_01_deletion_authorized | PASS | An explicit account deletion request must be recognized. |
| custom_02_access_request_not_deletion | PASS | An access/export request must not be treated as deletion authorization. |
| custom_03_identifier_overrides_anonymized_claim | PASS | A direct email remains identifying even if a status label says anonymized. |
| custom_04_legacy_contact_index_requires_delete | PASS | A secondary contact lookup index must be deleted, not merely redacted. |
| custom_05_active_flow_policy | PASS | A data flow must be disabled before deletion can be complete. |
| custom_06_timezone_normalization | PASS | Audit cutoffs are normalized to UTC. |
| custom_07_future_evidence_cannot_prove_past_state | PASS | Evidence captured after audit_at must not prove the earlier state. |
| custom_08_sql_missing_timestamp_uses_capture_time | PASS | SQL observations without row timestamps use the evidence capture time. |

Custom checks run: 8/8 passed.

## Full dataset output validation

- Valid: **True**
- Rows: 518
- Status counts: `{"COMPLETE": 164, "INCOMPLETE": 344, "NOT_APPLICABLE": 10}`
- Structural errors: 0

Validation checks cover the exact header, row count, ID coverage and uniqueness, lexical ordering, allowed statuses, JSON arrays, exact step schema, consecutive numbering, and the output-phase contract.

## Mismatches requiring review

| Case | Predicted status | Expected status | Predicted steps | Expected steps |
|---|---|---|---:|---:|
| case_04 | COMPLETE | COMPLETE | 1 | 2 |
| case_18 | INCOMPLETE | INCOMPLETE | 12 | 14 |
| case_20 | INCOMPLETE | INCOMPLETE | 6 | 8 |
| case_21 | COMPLETE | COMPLETE | 1 | 3 |
| case_22 | INCOMPLETE | INCOMPLETE | 7 | 8 |
| case_23 | INCOMPLETE | INCOMPLETE | 7 | 8 |
| case_25 | COMPLETE | COMPLETE | 1 | 3 |
| case_26 | COMPLETE | COMPLETE | 5 | 6 |
| case_27 | COMPLETE | COMPLETE | 5 | 6 |
| case_28 | COMPLETE | COMPLETE | 5 | 6 |
| case_29 | INCOMPLETE | INCOMPLETE | 13 | 14 |
| case_30 | INCOMPLETE | INCOMPLETE | 13 | 14 |
| case_31 | COMPLETE | COMPLETE | 2 | 3 |
| case_32 | INCOMPLETE | INCOMPLETE | 4 | 5 |

## Failures found and improvements made

- The first baseline was run without `pypdf` installed, so PDF evidence was silently skipped. Added `requirements.txt`, installed the dependency for local validation, and documented the setup command.
- Status text such as “anonymized” must not override an exposed email or stable user reference. The analytics state inference now treats direct identifiers and stable references as `PRESENT` before considering anonymization claims.
- Log readback events can omit source/index metadata present earlier in the same trace. Trace parsing now carries forward selected source and lookup metadata to classify secondary contact indexes correctly.
- Worker events can be recorded shortly after the dashboard report timestamp. The bounded correlation window was widened from five to ten minutes; this remains a heuristic and is a source of potential false associations that needs continued review.
- Scope selection now excludes observations created or observed after `audit_at`, including resources that are close in wall-clock time but are future evidence. A dedicated custom check protects this temporal boundary.
- SQL rows without a row-level `updated_at` or `observed_at` now use the evidence manifest's capture time instead of an artificial minimum timestamp; a custom regression test covers this point-in-time behavior.
- An authorized request is no longer marked `COMPLETE` when no pre-cutoff resource state can prove deletion. Such cases remain `INCOMPLETE` rather than treating missing evidence as proof of absence.
- Remaining public-sample mismatches indicate incomplete discovery of opaque resources and/or missing verification steps. These must be reviewed from the evidence and timestamps rather than fixed with case-specific labels.

## Limitations

- This is a deterministic evidence parser and policy engine; no external LLM/VLM was called. The image-derived observations are loaded from the reviewed local cache `code/media_evidence.json`.
- Public sample accuracy is not a guarantee of hidden-set accuracy. In particular, opaque resources without identity fields require stronger evidence linking and careful temporal reasoning.
- Exact-row score remains below target because some participant-visible evidence does not unambiguously link subjectless records to a specific user. The implementation deliberately avoids broad timestamp-only joins that would create false positives across interleaved deletion workflows.
