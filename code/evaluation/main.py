#!/usr/bin/env python3
"""Evaluate the deletion-audit agent against public examples and custom checks."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
sys.path.insert(0, str(ROOT / "code"))

from main import (  # noqa: E402
    AuditAgent,
    EvidenceParser,
    authorized_deletion,
    category_for,
    infer_state,
    parse_time,
    resource_policy,
    read_csv,
)

STEP_FIELDS = (
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
)
SIGNATURE_FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def step_signature(step: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(step.get(key, "") for key in SIGNATURE_FIELDS)


def public_sample_metrics(agent: AuditAgent) -> dict[str, Any]:
    requests = read_csv(DATASET / "sample_deletion_requests.csv")
    expected_rows = read_csv(DATASET / "sample_output.csv")
    expected = {row["case_id"]: row for row in expected_rows}
    predictions = [agent.audit_case(row) for row in requests]
    predicted = {row["case_id"]: row for row in predictions}

    status_correct = sum(
        predicted[cid]["deletion_status"] == expected[cid]["deletion_status"]
        for cid in expected
    )
    exact_rows = 0
    sequence_correct = 0
    field_matches = 0
    field_total = 0
    predicted_steps = 0
    expected_steps = 0
    matched_steps = 0
    mismatches: list[dict[str, Any]] = []

    for cid in expected:
        pred_steps = json.loads(predicted[cid]["steps_json"])
        gold_steps = json.loads(expected[cid]["steps_json"])
        pred_sig = [step_signature(step) for step in pred_steps]
        gold_sig = [step_signature(step) for step in gold_steps]
        predicted_steps += len(pred_sig)
        expected_steps += len(gold_sig)
        overlap = Counter(pred_sig) & Counter(gold_sig)
        matched_steps += sum(overlap.values())
        if predicted[cid]["deletion_status"] == expected[cid]["deletion_status"] and pred_sig == gold_sig:
            exact_rows += 1
            sequence_correct += 1
        elif pred_sig == gold_sig:
            sequence_correct += 1

        max_len = max(len(pred_steps), len(gold_steps))
        for idx in range(max_len):
            pred_step = pred_steps[idx] if idx < len(pred_steps) else {}
            gold_step = gold_steps[idx] if idx < len(gold_steps) else {}
            for field in STEP_FIELDS:
                field_total += 1
                if idx < len(pred_steps) and idx < len(gold_steps) and pred_step.get(field, "") == gold_step.get(field, ""):
                    field_matches += 1

        if predicted[cid]["deletion_status"] != expected[cid]["deletion_status"] or pred_sig != gold_sig:
            mismatches.append({
                "case_id": cid,
                "predicted_status": predicted[cid]["deletion_status"],
                "expected_status": expected[cid]["deletion_status"],
                "predicted_steps": len(pred_steps),
                "expected_steps": len(gold_steps),
            })

    precision = matched_steps / predicted_steps if predicted_steps else 1.0
    recall = matched_steps / expected_steps if expected_steps else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "sample_count": len(expected),
        "status_correct": status_correct,
        "status_accuracy": status_correct / len(expected) if expected else 0.0,
        "exact_rows": exact_rows,
        "row_accuracy": exact_rows / len(expected) if expected else 0.0,
        "sequence_correct": sequence_correct,
        "sequence_accuracy": sequence_correct / len(expected) if expected else 0.0,
        "field_matches": field_matches,
        "field_total": field_total,
        "field_accuracy": field_matches / field_total if field_total else 0.0,
        "predicted_steps": predicted_steps,
        "expected_steps": expected_steps,
        "matched_steps": matched_steps,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "mismatches": mismatches,
    }


def custom_checks(agent: AuditAgent) -> list[dict[str, Any]]:
    # SQL snapshots without a row-level timestamp must use the manifest's
    # capture time, not datetime.min (which would misrepresent the observation
    # as predating every audit cutoff).
    captured = parse_time("2026-09-15T12:00:00Z")
    with tempfile.TemporaryDirectory() as tmp_dir:
        sql_path = Path(tmp_dir) / "snapshot.sql"
        sql_path.write_text(
            "CREATE TABLE customer_profiles (resource_id TEXT, email TEXT);"
            "INSERT INTO customer_profiles VALUES ('account_test', 'person@example.com');",
            encoding="utf-8",
        )
        parser = EvidenceParser(Path(tmp_dir))
        parser.parse_sql(sql_path, "evidence_test", captured)
        sql_missing_timestamp_uses_capture_time = (
            len(parser.observations) == 1
            and parser.observations[0].observed_at == captured
        )

    checks = [
        (
            "custom_01_deletion_authorized",
            authorized_deletion("Please delete my account and personal data."),
            True,
            "An explicit account deletion request must be recognized.",
        ),
        (
            "custom_02_access_request_not_deletion",
            authorized_deletion("Please send me a copy of my account information."),
            False,
            "An access/export request must not be treated as deletion authorization.",
        ),
        (
            "custom_03_identifier_overrides_anonymized_claim",
            infer_state("analytics_platform", "analytics_test", {"email": "person@example.com", "status": "anonymized"}),
            "PRESENT",
            "A direct email remains identifying even if a status label says anonymized.",
        ),
        (
            "custom_04_legacy_contact_index_requires_delete",
            category_for("support_platform", "support_test", {"source": "legacy_contact_index"}),
            "DELETE",
            "A secondary contact lookup index must be deleted, not merely redacted.",
        ),
        (
            "custom_05_active_flow_policy",
            resource_policy("data_flow_test", "integration_service", "DISABLE")["required"],
            "DISABLED",
            "A data flow must be disabled before deletion can be complete.",
        ),
        (
            "custom_06_timezone_normalization",
            parse_time("2026-09-01T12:00:00Z") == datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc),
            True,
            "Audit cutoffs are normalized to UTC.",
        ),
        (
            "custom_07_future_evidence_cannot_prove_past_state",
            agent.latest_state("account_7566", parse_time("2026-01-01T00:00:00Z")) is None,
            True,
            "Evidence captured after audit_at must not prove the earlier state.",
        ),
        (
            "custom_08_sql_missing_timestamp_uses_capture_time",
            sql_missing_timestamp_uses_capture_time,
            True,
            "SQL observations without row timestamps use the evidence capture time.",
        ),
    ]
    return [
        {"case_id": case_id, "passed": actual == expected, "expected": expected, "actual": actual, "purpose": purpose}
        for case_id, actual, expected, purpose in checks
    ]


def validate_full_output() -> dict[str, Any]:
    output_path = ROOT / "output.csv"
    requests = load_rows(DATASET / "deletion_requests.csv")
    if not output_path.exists():
        return {"exists": False, "valid": False, "errors": ["output.csv is missing"]}
    rows = load_rows(output_path)
    errors: list[str] = []
    if len(rows) != len(requests):
        errors.append(f"Expected {len(requests)} rows, found {len(rows)}")
    if output_path.read_text(encoding="utf-8-sig").splitlines()[0] != "case_id,deletion_status,steps_json":
        errors.append("Incorrect output header")
    ids = [row.get("case_id", "") for row in rows]
    if ids != sorted(ids):
        errors.append("Rows are not lexicographically sorted by case_id")
    if len(set(ids)) != len(ids):
        errors.append("Duplicate case_id values found")
    request_ids = {row["case_id"] for row in requests}
    if set(ids) != request_ids:
        errors.append("Output case IDs do not match request case IDs")
    valid_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    operation_states = {
        "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
        "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
        "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
        "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
        "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
        "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
        "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
        "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
        "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
        "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
        "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
        "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
        "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
        "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
        "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
    }
    evidence_ids = {row["file_id"] for row in read_csv(DATASET / "evidence_files.csv")}
    evidence_ids.update(row["activity_id"] for row in read_csv(DATASET / "system_activity.csv"))
    evidence_ids.update(row["audit_id"] for row in read_csv(DATASET / "user_audit_log.csv"))
    for row in rows:
        if row.get("deletion_status") not in valid_statuses:
            errors.append(f"{row.get('case_id')}: invalid deletion_status")
        try:
            steps = json.loads(row.get("steps_json", ""))
            if not isinstance(steps, list):
                raise ValueError("steps_json is not an array")
            if [step.get("step_no") for step in steps] != list(range(1, len(steps) + 1)):
                errors.append(f"{row.get('case_id')}: step numbers are not consecutive")
            for step in steps:
                if set(step) != set(STEP_FIELDS):
                    errors.append(f"{row.get('case_id')}: step schema mismatch")
                    break
            if row.get("deletion_status") == "NOT_APPLICABLE" and steps:
                errors.append(f"{row.get('case_id')}: NOT_APPLICABLE must have no steps")
            if row.get("deletion_status") == "COMPLETE" and not steps:
                errors.append(f"{row.get('case_id')}: COMPLETE requires evidence-backed verification steps")
            if row.get("deletion_status") == "COMPLETE" and any(step.get("phase") != "VERIFICATION" for step in steps):
                errors.append(f"{row.get('case_id')}: COMPLETE contains non-verification steps")
            if [phase_order.get(step.get("phase"), -1) for step in steps] != sorted(phase_order.get(step.get("phase"), -1) for step in steps):
                errors.append(f"{row.get('case_id')}: phases are out of order")
            for step in steps:
                expected_pair = operation_states.get(step.get("operation"))
                if expected_pair != (step.get("phase"), step.get("state")):
                    errors.append(f"{row.get('case_id')}: invalid operation/phase/state combination")
                evidence_id = step.get("evidence_id", "")
                if step.get("phase") == "FINDING" and (not evidence_id or evidence_id not in evidence_ids):
                    errors.append(f"{row.get('case_id')}: finding has missing or unknown evidence")
                if row.get("deletion_status") == "COMPLETE" and step.get("phase") == "VERIFICATION" and (not evidence_id or evidence_id not in evidence_ids):
                    errors.append(f"{row.get('case_id')}: COMPLETE verification has missing or unknown evidence")
                if row.get("deletion_status") == "INCOMPLETE" and step.get("phase") in {"REMEDIATION", "VERIFICATION"} and evidence_id:
                    errors.append(f"{row.get('case_id')}: future action must have empty evidence_id")
        except (json.JSONDecodeError, ValueError, AttributeError) as exc:
            errors.append(f"{row.get('case_id')}: invalid steps_json ({exc})")
    return {
        "exists": True,
        "valid": not errors,
        "row_count": len(rows),
        "status_counts": {status: sum(row.get("deletion_status") == status for row in rows) for status in sorted(valid_statuses)},
        "errors": errors[:50],
        "error_count": len(errors),
    }


def main() -> int:
    agent = AuditAgent(DATASET)
    sample = public_sample_metrics(agent)
    custom = custom_checks(agent)
    full = validate_full_output()
    report_path = Path(__file__).resolve().parent / "evaluation_report.md"
    mismatch_lines = [
        f"| {item['case_id']} | {item['predicted_status']} | {item['expected_status']} | {item['predicted_steps']} | {item['expected_steps']} |"
        for item in sample["mismatches"]
    ] or ["| None | — | — | — | — |"]
    custom_lines = [
        f"| {item['case_id']} | {'PASS' if item['passed'] else 'FAIL'} | {item['purpose']} |"
        for item in custom
    ]
    report = f"""# Evaluation Report

Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}

## Public sample evaluation

The agent is evaluated against all {sample['sample_count']} public labeled examples in `dataset/sample_output.csv`. These are validation cases, not labels used by the prediction algorithm.

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | {sample['status_correct']}/{sample['sample_count']} ({sample['status_accuracy']:.2%}) |
| Exact row accuracy (status + complete ordered steps) | {sample['exact_rows']}/{sample['sample_count']} ({sample['row_accuracy']:.2%}) |
| Sequence accuracy | {sample['sequence_correct']}/{sample['sample_count']} ({sample['sequence_accuracy']:.2%}) |
| Field accuracy (seven step fields, index-aligned; missing steps count as incorrect) | {sample['field_matches']}/{sample['field_total']} ({sample['field_accuracy']:.2%}) |
| Step precision / recall / F1 (exact step signatures, order-independent) | {sample['step_precision']:.2%} / {sample['step_recall']:.2%} / {sample['step_f1']:.2%} |

## Additional participant-created evaluation cases

| Case | Result | Purpose |
|---|---|---|
{chr(10).join(custom_lines)}

Custom checks run: {sum(item['passed'] for item in custom)}/{len(custom)} passed.

## Full dataset output validation

- Valid: **{full.get('valid', False)}**
- Rows: {full.get('row_count', 0)}
- Status counts: `{json.dumps(full.get('status_counts', {}), sort_keys=True)}`
- Structural errors: {full.get('error_count', len(full.get('errors', [])))}

Validation checks cover the exact header, row count, ID coverage and uniqueness, lexical ordering, allowed statuses, JSON arrays, exact step schema, consecutive numbering, and the output-phase contract.

## Mismatches requiring review

| Case | Predicted status | Expected status | Predicted steps | Expected steps |
|---|---|---|---:|---:|
{chr(10).join(mismatch_lines)}

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
"""
    report_path.write_text(report, encoding="utf-8")
    print(json.dumps({"sample": sample, "custom_checks": custom, "full_output": full, "report": str(report_path)}, indent=2, default=str))
    return 0 if full.get("valid") and all(item["passed"] for item in custom) else 1


if __name__ == "__main__":
    raise SystemExit(main())
