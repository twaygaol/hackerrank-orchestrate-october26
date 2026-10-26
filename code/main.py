#!/usr/bin/env python3
"""Evidence-backed deletion audit agent for Ghost Data Still Exists.

The implementation deliberately separates two questions:

1. Which resources belong to a person?  Resource discovery may use all supplied
   participant-facing evidence, because a later readback can reveal that a
   previously opaque resource id belonged to the subject.
2. What was the resource state at the case's audit cutoff?  Status decisions
   use only observations at or before ``audit_at`` from evidence captured at or
   before that cutoff.

This prevents a later snapshot from changing an earlier audit verdict while
still allowing current and historical identifiers to be reconstructed.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"

NULLS = {"", "null", "none", "nil", "n/a", "[redacted]", "redacted"}
RESOURCE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:account|search|cache|support|analytics|telemetry|"
    r"export|object|marketing|email_delivery|audit_record|legal_hold|backup|"
    r"data_flow|tombstone)_\d+\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
USER_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S+)")

FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def norm(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().casefold().split())


def truthy(value: Any) -> bool:
    return norm(value) in {"1", "true", "yes", "enabled", "active", "allowed"}


def non_null(value: Any) -> bool:
    return norm(value) not in NULLS


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def scalar_values(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for child in value.values():
            yield from scalar_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from scalar_values(child)
    elif value is not None:
        yield str(value)


def flatten_dict(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else key
            if isinstance(child, (dict, list)):
                result.update(flatten_dict(child, name))
            else:
                result[name] = child
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.update(flatten_dict(child, f"{prefix}[{index}]"))
    return result


def infer_system(resource_id: str, hint: str = "") -> str:
    prefix = resource_id.casefold()
    mapping = (
        ("audit_record_", "security_service"),
        ("legal_hold_", "legal_retention_service"),
        ("email_delivery_", "email_delivery_service"),
        ("data_flow_", "integration_service"),
        ("tombstone_", "identity_service"),
        ("account_", "account_service"),
        ("search_", "search_service"),
        ("cache_", "cache_service"),
        ("support_", "support_platform"),
        ("analytics_", "analytics_platform"),
        ("telemetry_", "telemetry_platform"),
        ("export_", "export_service"),
        ("object_", "object_storage"),
        ("marketing_", "marketing_platform"),
        ("backup_", "backup_service"),
    )
    for marker, system in mapping:
        if prefix.startswith(marker):
            return system
    hint = hint.casefold().strip()
    aliases = {
        "customer_account_service": "account_service",
        "customer_search_service": "search_service",
        "object_store": "export_service",
        "archive_service": "security_service",
    }
    return aliases.get(hint, hint or "unknown_service")


def category_for(system: str, resource_id: str, raw: dict[str, Any]) -> str:
    rid = resource_id.casefold()
    raw_text = " ".join(str(v) for v in raw.values()).casefold()
    if "contact_lookup" in raw_text or "email_opt_in" in raw_text:
        return "DELETE"
    if rid.startswith("account_"):
        return "DELETE"
    if rid.startswith(("search_", "cache_", "export_", "object_", "marketing_")):
        return "DELETE"
    if rid.startswith("support_"):
        if (
            ("attachment" in raw_text and "message" not in raw_text)
            or "contact_query" in raw_text
            or "legacy_contact_index" in raw_text
            or "contact_lookup" in raw_text
        ):
            return "DELETE"
        return "REDACT"
    if rid.startswith(("analytics_", "telemetry_")):
        return "ANONYMIZE"
    if rid.startswith(("email_delivery_", "tombstone_")):
        return "REDACT"
    if rid.startswith("data_flow_"):
        return "DISABLE"
    if rid.startswith("backup_"):
        return "BLOCK"
    if rid.startswith(("audit_record_", "legal_hold_")):
        return "RETAIN"
    if system in {"analytics_platform", "telemetry_platform"}:
        return "ANONYMIZE"
    return "DELETE"


IDENTITY_KEYS = {
    "user_id",
    "customer_reference",
    "customer_email",
    "subject_reference",
    "subject_ref",
    "owner_email",
    "owner_phone",
    "requester_email",
    "requester_phone",
    "requester_name",
    "email",
    "email_hash",
    "phone",
    "full_name",
    "display_name",
    "lookup_key",
    "match_key",
    "subject_key",
    "owner_key",
    "scan_key",
    "query",
    "correlation_key",
    "matched_value",
}


def identity_values(raw: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key, value in raw.items():
        simple = key.rsplit(".", 1)[-1].split("[")[0].casefold()
        if simple in IDENTITY_KEYS and non_null(value):
            values.add(norm(value))
    joined = " ".join(str(v) for v in raw.values() if v is not None)
    values.update(norm(item) for item in EMAIL_RE.findall(joined))
    values.update(norm(item) for item in HASH_RE.findall(joined))
    values.update(norm(item) for item in USER_RE.findall(joined))
    values.discard("")
    values.difference_update(NULLS)
    return values


def get_field(raw: dict[str, Any], *names: str) -> Any:
    wanted = {name.casefold() for name in names}
    for key, value in raw.items():
        simple = key.rsplit(".", 1)[-1].split("[")[0].casefold()
        if simple in wanted:
            return value
    return None


def direct_identifiers_present(raw: dict[str, Any]) -> bool:
    direct_keys = {
        "email",
        "customer_email",
        "owner_email",
        "requester_email",
        "email_hash",
        "phone",
        "owner_phone",
        "requester_phone",
        "full_name",
        "display_name",
        "requester_name",
        "name",
    }
    for key, value in raw.items():
        simple = key.rsplit(".", 1)[-1].split("[")[0].casefold()
        if simple in direct_keys and non_null(value):
            return True
    return False


def infer_state(system: str, resource_id: str, raw: dict[str, Any]) -> str:
    rid = resource_id.casefold()
    raw_text = " ".join(str(v) for v in raw.values()).casefold()
    event = norm(get_field(raw, "event"))
    result = norm(get_field(raw, "result"))
    rows = norm(get_field(raw, "rows"))
    status_code = norm(get_field(raw, "status_code", "http_status"))

    if rid.startswith("account_"):
        profile = raw.get("profile", "__missing__")
        if (
            status_code == "404"
            or rows == "0"
            or result in {"miss", "not_found", "absent"}
            or "not_found" in raw_text
        ):
            return "ABSENT"
        if profile is None:
            return "ABSENT"
        return "PRESENT"

    if rid.startswith(("search_", "cache_")):
        total = norm(get_field(raw, "total", "total_hits"))
        if (
            result in {"miss", "not_found", "absent"}
            or total == "0"
            or rows == "0"
            or "not_found" in raw_text
        ):
            return "ABSENT"
        return "PRESENT"

    if rid.startswith(("analytics_", "telemetry_")):
        reference = get_field(raw, "customer_reference", "subject_reference", "user_id")
        # Treat status words as claims, not proof: a direct identifier or a
        # stable subject reference means this record is still linkable.
        contains_email = bool(EMAIL_RE.search(" ".join(str(v) for v in raw.values())))
        if direct_identifiers_present(raw) or contains_email or non_null(reference):
            return "PRESENT"
        if "anonymized" in raw_text:
            return "ANONYMIZED"
        return "ANONYMIZED"

    if rid.startswith("support_"):
        if event and "not_found" in event:
            return "ABSENT"
        message = norm(get_field(raw, "message_text", "message"))
        if direct_identifiers_present(raw) or EMAIL_RE.search(" ".join(map(str, raw.values()))):
            return "PRESENT"
        if "redacted" in raw_text or message in {"[redacted]", "redacted"} or non_null(
            get_field(raw, "customer_reference", "subject_reference")
        ):
            return "REDACTED"
        return "REDACTED"

    if rid.startswith("data_flow_"):
        if "| disabled |" in raw_text or "enabled=false" in raw_text:
            return "DISABLED"
        if "| active |" in raw_text or "enabled=true" in raw_text:
            return "ACTIVE"
        enabled = get_field(raw, "enabled", "scheduler_registered")
        return "ACTIVE" if truthy(enabled) else "DISABLED"

    if rid.startswith("backup_"):
        if "blocked" in raw_text or "restore_allowed=false" in raw_text:
            return "BLOCKED"
        if "restore_allowed=true" in raw_text or "| active |" in raw_text:
            return "ACTIVE"
        allowed = get_field(raw, "restore_allowed", "eligible")
        blocked = get_field(raw, "deletion_block", "blocked")
        if truthy(allowed) and not truthy(blocked):
            return "ACTIVE"
        return "BLOCKED"

    if rid.startswith(("audit_record_", "legal_hold_")):
        return "PRESENT" if rows != "0" else "ABSENT"

    if rid.startswith("export_"):
        available = get_field(raw, "available", "object_present")
        if available is not None and not truthy(available):
            return "ABSENT"
        if rows == "0" or status_code == "404" or result in {"miss", "not_found", "absent"}:
            return "ABSENT"
        return "PRESENT"

    if rid.startswith("tombstone_"):
        return "PRESENT" if direct_identifiers_present(raw) else "REDACTED"

    if rid.startswith(("marketing_", "email_delivery_")):
        return "PRESENT" if direct_identifiers_present(raw) else "REDACTED"

    return "PRESENT"


@dataclass
class Observation:
    resource_id: str
    system_id: str
    state: str
    observed_at: datetime
    evidence_id: str
    captured_at: datetime
    identifiers: set[str] = field(default_factory=set)
    raw_text: str = ""
    category: str = "DELETE"


@dataclass
class EvidenceScope:
    evidence_id: str
    captured_at: datetime
    observed_at: datetime
    systems: set[str]
    resources: dict[str, set[str]]
    is_inventory: bool = False


class EvidenceParser:
    def __init__(self, dataset: Path):
        self.dataset = dataset
        self.observations: list[Observation] = []
        self.scopes: list[EvidenceScope] = []

    def add_observation(
        self,
        resource_id: str,
        raw: dict[str, Any],
        evidence_id: str,
        captured_at: datetime,
        observed_at: datetime | None = None,
        system_hint: str = "",
    ) -> None:
        rid = resource_id.strip()
        system = infer_system(rid, system_hint)
        flattened = flatten_dict(raw)
        if not flattened:
            flattened = dict(raw)
        state = infer_state(system, rid, flattened | ({"profile": raw.get("profile")} if "profile" in raw else {}))
        self.observations.append(
            Observation(
                resource_id=rid,
                system_id=system,
                state=state,
                observed_at=observed_at or captured_at,
                evidence_id=evidence_id,
                captured_at=captured_at,
                identifiers=identity_values(flattened),
                raw_text=" ".join(scalar_values(raw)).casefold(),
                category=category_for(system, rid, flattened),
            )
        )

    def parse_all(self) -> tuple[list[Observation], list[EvidenceScope]]:
        manifest = read_csv(self.dataset / "evidence_files.csv")
        for item in manifest:
            path = self.dataset / item["file_path"]
            captured = parse_time(item["captured_at"])
            suffix = path.suffix.casefold()
            if suffix == ".json":
                self.parse_json(path, item["file_id"], captured)
            elif suffix == ".sql":
                self.parse_sql(path, item["file_id"], captured)
            elif suffix in {".log", ".txt"}:
                self.parse_log(path, item["file_id"], captured)
            elif suffix == ".pdf":
                self.parse_pdf(path, item["file_id"], captured)
        self.parse_media_cache()
        return self.observations, self.scopes

    def parse_json(self, path: Path, evidence_id: str, captured: datetime) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        resources_by_system: dict[str, set[str]] = defaultdict(set)
        systems_seen: set[str] = set()

        def walk(value: Any, inherited: dict[str, Any], path_parts: list[str]) -> None:
            if isinstance(value, dict):
                local = dict(inherited)
                for key in ("captured_at", "observed_at", "updated_at", "exported_at"):
                    if key in value:
                        local[key] = value[key]
                system_hint = str(value.get("data_store") or local.get("system_hint") or "")
                if path_parts and path_parts[-1].endswith("_service") or (
                    path_parts and path_parts[-1].endswith("_platform")
                ):
                    system_hint = path_parts[-1]
                local["system_hint"] = system_hint

                resource_id = value.get("resource_id")
                if isinstance(resource_id, str):
                    timestamp = parse_time(
                        value.get("observed_at")
                        or value.get("captured_at")
                        or value.get("updated_at")
                        or local.get("captured_at")
                        or local.get("exported_at")
                    )
                    self.add_observation(
                        resource_id,
                        value,
                        evidence_id,
                        captured,
                        timestamp,
                        system_hint,
                    )
                    system = infer_system(resource_id, system_hint)
                    resources_by_system[system].add(resource_id)
                    systems_seen.add(system)

                for key, child in value.items():
                    child_local = dict(local)
                    if key in {
                        "account_service",
                        "search_service",
                        "analytics_platform",
                        "support_platform",
                        "integration_service",
                        "backup_service",
                        "security_service",
                        "export_service",
                        "identity_service",
                        "marketing_platform",
                        "email_delivery_service",
                    }:
                        child_local["system_hint"] = key
                    walk(child, child_local, path_parts + [key])
            elif isinstance(value, list):
                for child in value:
                    walk(child, inherited, path_parts)

        walk(data, {"exported_at": data.get("exported_at") if isinstance(data, dict) else None}, [])
        if systems_seen:
            self.scopes.append(
                EvidenceScope(
                    evidence_id=evidence_id,
                    captured_at=captured,
                    observed_at=captured,
                    systems=systems_seen,
                    resources=dict(resources_by_system),
                    is_inventory=False,
                )
            )

    def parse_sql(self, path: Path, evidence_id: str, captured: datetime) -> None:
        try:
            script = path.read_text(encoding="utf-8")
            connection = sqlite3.connect(":memory:")
            connection.executescript(script)
        except (OSError, sqlite3.DatabaseError):
            return
        connection.row_factory = sqlite3.Row
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        table_system = {
            "customer_profiles": "account_service",
            "customer_search_documents": "search_service",
            "customer_analytics_profiles": "analytics_platform",
            "support_records": "support_platform",
            "customer_exports": "export_service",
            "connector_subscriptions": "integration_service",
            "backup_restore_entries": "backup_service",
            "security_audit_records": "security_service",
            "account_tombstones": "identity_service",
            "marketing_profiles": "marketing_platform",
            "email_delivery_logs": "email_delivery_service",
            "legal_hold_records": "legal_retention_service",
        }
        resources_by_system: dict[str, set[str]] = defaultdict(set)
        systems: set[str] = set()
        observed = captured
        if "snapshot_scope" in tables:
            try:
                for row in connection.execute("SELECT * FROM snapshot_scope"):
                    raw = dict(row)
                    systems.add(str(raw.get("origin_system")))
                    observed = max(observed, parse_time(raw.get("captured_at")))
            except sqlite3.DatabaseError:
                pass
        for table in tables:
            if table == "snapshot_scope":
                continue
            system_hint = table_system.get(table, "")
            try:
                rows = connection.execute(f'SELECT * FROM "{table}"').fetchall()
            except sqlite3.DatabaseError:
                continue
            for row in rows:
                raw = dict(row)
                rid = raw.get("resource_id")
                if not rid:
                    continue
                raw_row_time = raw.get("updated_at") or raw.get("observed_at")
                row_time = parse_time(raw_row_time) if raw_row_time else captured
                self.add_observation(
                    str(rid), raw, evidence_id, captured, row_time, system_hint
                )
                system = infer_system(str(rid), system_hint)
                systems.add(system)
                resources_by_system[system].add(str(rid))
        connection.close()
        if systems:
            self.scopes.append(
                EvidenceScope(
                    evidence_id=evidence_id,
                    captured_at=captured,
                    observed_at=observed,
                    systems=systems,
                    resources=dict(resources_by_system),
                    is_inventory=True,
                )
            )

    @staticmethod
    def parse_kv_line(line: str) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for key, value in KV_RE.findall(line):
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            data[key] = value
        return data

    def parse_log(self, path: Path, evidence_id: str, captured: datetime) -> None:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        traces: dict[str, dict[str, Any]] = defaultdict(dict)
        resources_by_system: dict[str, set[str]] = defaultdict(set)
        systems: set[str] = set()
        for line in lines:
            timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2}T[^ ]+)", line)
            observed = parse_time(timestamp_match.group(1)) if timestamp_match else captured
            payload: dict[str, Any]
            brace = line.find("{")
            if brace >= 0:
                try:
                    payload = json.loads(line[brace:])
                except json.JSONDecodeError:
                    payload = self.parse_kv_line(line)
            else:
                payload = self.parse_kv_line(line)
            payload["raw_line"] = line
            trace = str(payload.get("trace_id") or "")
            if trace:
                for key in IDENTITY_KEYS:
                    if key in payload and non_null(payload[key]):
                        traces[trace][key] = payload[key]
                # Preserve source/index metadata across a trace so a later
                # readback can still be classified as a secondary identifier
                # lookup even when the completion line omits that metadata.
                for key in (
                    "source", "index", "query_type", "lookup_type", "resource_type",
                    "object_type", "record_type", "data_store", "operation", "mode",
                ):
                    if key in payload and non_null(payload[key]):
                        traces[trace][key] = payload[key]
                if "resource_id" in payload:
                    traces[trace]["resource_id"] = payload["resource_id"]
            rid = payload.get("resource_id")
            if not rid:
                matches = RESOURCE_RE.findall(line)
                rid = matches[0] if matches else None
            if not rid:
                continue
            merged = dict(traces.get(trace, {}))
            merged.update(payload)
            event = norm(payload.get("event"))
            if event.endswith("_started"):
                continue
            service = str(payload.get("service") or payload.get("logger") or "")
            self.add_observation(str(rid), merged, evidence_id, captured, observed, service)
            system = infer_system(str(rid), service)
            systems.add(system)
            resources_by_system[system].add(str(rid))
        if systems:
            self.scopes.append(
                EvidenceScope(
                    evidence_id=evidence_id,
                    captured_at=captured,
                    observed_at=captured,
                    systems=systems,
                    resources=dict(resources_by_system),
                    is_inventory=False,
                )
            )

    def parse_pdf(self, path: Path, evidence_id: str, captured: datetime) -> None:
        text = ""
        try:
            from pypdf import PdfReader  # type: ignore

            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            return
        # Use the whole document as context. Business PDFs often place the
        # resource id, subject identifiers, and attachment classification in
        # different table rows or even on different pages.
        lines = text.splitlines()
        for index, line in enumerate(lines):
            resources = RESOURCE_RE.findall(line)
            if not resources:
                continue
            context = " ".join(lines)
            raw = self.parse_kv_line(context)
            raw["raw_line"] = context
            for rid in resources:
                self.add_observation(rid, raw, evidence_id, captured, captured)

    def parse_media_cache(self) -> None:
        cache = ROOT / "code" / "media_evidence.json"
        if not cache.exists():
            return
        try:
            items = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        manifest = {row["file_id"]: row for row in read_csv(self.dataset / "evidence_files.csv")}
        for item in items:
            evidence_id = item["evidence_id"]
            meta = manifest.get(evidence_id, {})
            captured = parse_time(meta.get("captured_at"))
            raw = dict(item.get("fields", {}))
            raw.update({"state_hint": item.get("state")})
            self.add_observation(
                item["resource_id"],
                raw,
                evidence_id,
                captured,
                parse_time(item.get("observed_at")) if item.get("observed_at") else captured,
                item.get("system_id", ""),
            )
            self.observations[-1].state = item["state"]
            if item.get("category"):
                self.observations[-1].category = item["category"]


def build_identity_index(
    identities: list[dict[str, str]], audit_log: list[dict[str, str]]
) -> tuple[dict[str, dict[str, str]], dict[str, set[str]], dict[str, set[str]]]:
    users = {row["user_id"]: row for row in identities}
    values_by_user: dict[str, set[str]] = defaultdict(set)
    users_by_value: dict[str, set[str]] = defaultdict(set)

    def add(user_id: str, value: Any) -> None:
        normalized = norm(value)
        if not normalized or normalized in NULLS:
            return
        values_by_user[user_id].add(normalized)
        users_by_value[normalized].add(user_id)

    for row in identities:
        for key in ("user_id", "name", "email", "phone", "email_hash"):
            add(row["user_id"], row.get(key))
    for row in audit_log:
        add(row["user_id"], row.get("old_value"))
        add(row["user_id"], row.get("new_value"))
    return users, values_by_user, users_by_value


def authorized_deletion(text: str) -> bool:
    lowered = text.casefold()
    non_deletion = (
        "marketing lists only",
        "promotional emails",
        "download my account information",
        "copy of the information",
        "what personal information",
        "copy of last year's invoices",
        "resetting the login",
        "misspelled",
        "out of date",
        "change the email address",
    )
    if any(phrase in lowered for phrase in non_deletion):
        return False
    deletion_markers = (
        "delet",
        "eras",
        "remove my account",
        "remove my profile",
        "remove records",
        "remove any remaining",
        "close my account",
        "close this account",
        "close the account",
        "close account",
        "would like it closed",
        "account page is gone",
        "account was deleted",
        "account had been deleted",
        "profile is gone",
        "privacy page still says my request failed",
        "audit the deletion",
        "suppression définitive",
        "eliminar mi cuenta",
        "eliminación permanente",
        "exclusão permanente",
        "영구 삭제",
        "完全な削除",
    )
    return any(marker in lowered for marker in deletion_markers)


def resource_policy(resource_id: str, system_id: str, category: str) -> dict[str, str]:
    if category == "DELETE":
        return {
            "required": "ABSENT",
            "finding": "REPORT_REMAINING_RECORD",
            "remediation": "DELETE_RECORD",
            "verification": "VERIFY_RECORD_ABSENT",
        }
    if category == "REDACT":
        return {
            "required": "REDACTED",
            "finding": "REPORT_EXPOSED_PII",
            "remediation": "REDACT_RECORD",
            "verification": "VERIFY_RECORD_REDACTED",
        }
    if category == "ANONYMIZE":
        return {
            "required": "ANONYMIZED",
            "finding": "REPORT_EXPOSED_PII",
            "remediation": "ANONYMIZE_RECORD",
            "verification": "VERIFY_RECORD_ANONYMIZED",
        }
    if category == "DISABLE":
        return {
            "required": "DISABLED",
            "finding": "REPORT_ACTIVE_DATA_FLOW",
            "remediation": "DISABLE_DATA_FLOW",
            "verification": "VERIFY_DATA_FLOW_DISABLED",
        }
    if category == "BLOCK":
        return {
            "required": "BLOCKED",
            "finding": "REPORT_RESTORE_RISK",
            "remediation": "BLOCK_RESTORE",
            "verification": "VERIFY_RESTORE_BLOCKED",
        }
    return {
        "required": "PRESENT",
        "finding": "",
        "remediation": "",
        "verification": "VERIFY_RECORD_PRESENT",
    }


class AuditAgent:
    def __init__(self, dataset: Path):
        self.dataset = dataset
        self.evidence_origins = {
            row["file_id"]: row.get("origin", "")
            for row in read_csv(dataset / "evidence_files.csv")
        }
        self.identities = read_csv(dataset / "user_identities.csv")
        self.audit_log = read_csv(dataset / "user_audit_log.csv")
        self.activities = read_csv(dataset / "system_activity.csv")
        self.users, self.values_by_user, self.users_by_value = build_identity_index(
            self.identities, self.audit_log
        )
        parser = EvidenceParser(dataset)
        self.observations, self.scopes = parser.parse_all()
        self.observations_by_resource: dict[str, list[Observation]] = defaultdict(list)
        self.resources_by_user: dict[str, set[str]] = defaultdict(set)
        self.resource_users: dict[str, set[str]] = defaultdict(set)
        for observation in self.observations:
            self.observations_by_resource[observation.resource_id].append(observation)
        self._link_resources()
        self._load_activity_links()
        self._propagate_workflow_links()
        self._link_opaque_analytics_from_audit_context()

    def _link_resources(self) -> None:
        # First use parsed identity fields. Then use substring matching to catch
        # identifiers embedded in support messages and document prose.
        for observation in self.observations:
            matched_users: set[str] = set()
            for value in observation.identifiers:
                matched_users.update(self.users_by_value.get(value, set()))
            for user_id in matched_users:
                self.resources_by_user[user_id].add(observation.resource_id)
                self.resource_users[observation.resource_id].add(user_id)

    def _load_activity_links(self) -> None:
        for row in self.activities:
            if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
                continue
            # Match explicit identity tokens, not arbitrary substrings. The
            # old substring check allowed user_1 to match user_10 and could
            # attach decoy resources to the wrong subject.
            raw = " ".join(row.values()).casefold()
            tokens = {norm(value) for value in USER_RE.findall(raw)}
            tokens.update(norm(value) for value in EMAIL_RE.findall(raw))
            matched: set[str] = set()
            for token in tokens:
                matched.update(self.users_by_value.get(token, set()))
            rid = row["resource_id"]
            if not RESOURCE_RE.fullmatch(rid):
                continue
            explicit_emails = {
                value
                for obs in self.observations_by_resource.get(rid, [])
                for value in obs.identifiers
                if "@" in value
            }
            if explicit_emails:
                matched = {
                    user_id
                    for user_id in matched
                    if explicit_emails & self.values_by_user.get(user_id, set())
                }
            for user_id in matched:
                self.resources_by_user[user_id].add(rid)
                self.resource_users[rid].add(user_id)
            if matched:
                system = infer_system(rid, row.get("target_system", ""))
                raw_fields = dict(row)
                self.observations.append(
                    Observation(
                        resource_id=rid,
                        system_id=system,
                        state="PRESENT",
                        observed_at=parse_time(row.get("event_time")),
                        evidence_id=row["activity_id"],
                        captured_at=parse_time(row.get("event_time")),
                        identifiers=identity_values(raw_fields),
                        raw_text=raw,
                        category=category_for(system, rid, raw_fields),
                    )
                )
                self.observations_by_resource[rid].append(self.observations[-1])

    def _propagate_workflow_links(self) -> None:
        """Link adjacent cross-operation workflow resources.

        Deletion workers batch the same operation for several subjects, so two
        adjacent DELETE events must not be joined. A transition such as
        ANONYMIZE -> REDACT -> DISABLE -> BLOCK within ten minutes, however,
        represents the ordered tail of one subject workflow. Propagating from a
        directly identified resource recovers opaque anonymized resource ids.
        """
        policy_types = {
            "DELETE_RECORD",
            "REDACT_RECORD",
            "ANONYMIZE_RECORD",
            "DISABLE_DATA_FLOW",
            "BLOCK_RESTORE",
        }
        events = sorted(
            (row for row in self.activities if row.get("event_type") in policy_types),
            key=lambda row: parse_time(row.get("event_time")),
        )
        for _ in range(4):
            changed = False
            for left, right in zip(events, events[1:]):
                if left["event_type"] == right["event_type"]:
                    continue
                gap = (
                    parse_time(right.get("event_time")) - parse_time(left.get("event_time"))
                ).total_seconds()
                if gap < 0 or gap > 600:
                    continue
                left_id, right_id = left["resource_id"], right["resource_id"]
                left_users = self.resource_users.get(left_id, set())
                right_users = self.resource_users.get(right_id, set())
                if len(left_users) == 1 and not right_users:
                    user_id = next(iter(left_users))
                    self.resource_users[right_id].add(user_id)
                    self.resources_by_user[user_id].add(right_id)
                    changed = True
                elif len(right_users) == 1 and not left_users:
                    user_id = next(iter(right_users))
                    self.resource_users[left_id].add(user_id)
                    self.resources_by_user[user_id].add(left_id)
                    changed = True
            if not changed:
                break

    def _link_opaque_analytics_from_audit_context(self) -> None:
        """Recover opaque analytics rows from narrowly scoped readback context.

        Some readback logs redact every analytics identifier but include a
        subject-linked security audit read in the same evidence file. Link only
        when the analytics observation is within 15 minutes of exactly one
        uniquely linked audit record; ties and wider gaps remain unassigned.
        """
        audit_observations = [
            obs
            for obs in self.observations
            if obs.resource_id.startswith("audit_record_")
            and len(self.resource_users.get(obs.resource_id, set())) == 1
        ]
        for observation in self.observations:
            if observation.category != "ANONYMIZE" or observation.identifiers:
                continue
            if not observation.resource_id.startswith("analytics_"):
                continue
            if self.evidence_origins.get(observation.evidence_id) != "service_readback_logs":
                continue
            candidates = [
                audit
                for audit in audit_observations
                if audit.evidence_id == observation.evidence_id
                and abs((audit.observed_at - observation.observed_at).total_seconds()) <= 900
            ]
            if not candidates:
                continue
            distances = [abs((audit.observed_at - observation.observed_at).total_seconds()) for audit in candidates]
            nearest_distance = min(distances)
            nearest = [audit for audit, distance in zip(candidates, distances) if distance == nearest_distance]
            nearest_users = {next(iter(self.resource_users[audit.resource_id])) for audit in nearest}
            if len(nearest) != 1 or len(nearest_users) != 1:
                continue
            user_id = next(iter(nearest_users))
            self.resources_by_user[user_id].add(observation.resource_id)
            self.resource_users[observation.resource_id].add(user_id)

    def resolve_user(self, email: str) -> str | None:
        candidates = self.users_by_value.get(norm(email), set())
        return sorted(candidates)[0] if candidates else None

    def latest_state(
        self, resource_id: str, audit_at: datetime
    ) -> Observation | None:
        eligible = [
            obs
            for obs in self.observations_by_resource.get(resource_id, [])
            if obs.observed_at <= audit_at and obs.captured_at <= audit_at
        ]
        if eligible:
            return max(eligible, key=lambda obs: (obs.observed_at, obs.captured_at, obs.evidence_id))

        # A full SQL inventory proves that a known resource is absent if its
        # system is in scope and the resource is not in the captured table.
        system = infer_system(resource_id)
        inventories = [
            scope
            for scope in self.scopes
            if scope.is_inventory
            and scope.captured_at <= audit_at
            and scope.observed_at <= audit_at
            and system in scope.systems
            and resource_id not in scope.resources.get(system, set())
        ]
        if inventories and resource_id.casefold().startswith(
            ("account_", "search_", "cache_", "export_", "marketing_")
        ):
            scope = max(inventories, key=lambda item: (item.observed_at, item.captured_at))
            return Observation(
                resource_id=resource_id,
                system_id=system,
                state="ABSENT",
                observed_at=scope.observed_at,
                evidence_id=scope.evidence_id,
                captured_at=scope.captured_at,
                category=category_for(system, resource_id, {}),
            )
        return None

    def audit_case(self, request: dict[str, str]) -> dict[str, str]:
        case_id = request["case_id"]
        if not authorized_deletion(request.get("request_text", "")):
            return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

        user_id = self.resolve_user(request.get("email", ""))
        if not user_id:
            return {"case_id": case_id, "deletion_status": "INCOMPLETE", "steps_json": "[]"}

        audit_at = parse_time(request.get("audit_at"))
        resources_set = set(self.resources_by_user.get(user_id, set()))
        reported_at = parse_time(request.get("reported_at"))
        near_report_resources: set[str] = set()
        policy_activity_types = {
            "DELETE_RECORD",
            "REDACT_RECORD",
            "ANONYMIZE_RECORD",
            "DISABLE_DATA_FLOW",
            "BLOCK_RESTORE",
            "RETAIN_RECORD",
        }
        for activity in self.activities:
            activity_time = parse_time(activity.get("event_time"))
            # Worker events can finish several minutes after the dashboard
            # status is reported. Use a bounded ten-minute correlation window
            # rather than requiring an arbitrary exact five-minute match.
            if abs((activity_time - reported_at).total_seconds()) > 600:
                continue
            if activity.get("event_type") not in policy_activity_types:
                continue
            rid = activity.get("resource_id", "")
            known_users = self.resource_users.get(rid, set())
            if RESOURCE_RE.fullmatch(rid) and (not known_users or user_id in known_users):
                resources_set.add(rid)
                near_report_resources.add(rid)

        # Focus the case on the newest participant evidence available by the
        # cutoff. A person can have several requests over the year; without
        # this temporal focus, resources from a later request would leak into
        # an earlier case for the same identity.
        eligible_evidence_observations = [
            obs
            for rid in resources_set
            for obs in self.observations_by_resource.get(rid, [])
            if obs.evidence_id.startswith("evidence_")
            and obs.captured_at <= audit_at
            and obs.observed_at <= audit_at
        ]
        focus_capture = (
            max(obs.captured_at for obs in eligible_evidence_observations)
            if eligible_evidence_observations
            else None
        )
        focused_resources: set[str] = set()
        for rid in resources_set:
            observations = self.observations_by_resource.get(rid, [])
            in_focus_file = focus_capture is not None and any(
                obs.evidence_id.startswith("evidence_")
                and obs.captured_at == focus_capture
                and obs.observed_at <= audit_at
                for obs in observations
            )
            # Evidence created after the audit cutoff must never expand the
            # subject's audit scope, even when it is close to audit_at.
            near_audit = any(
                obs.observed_at <= audit_at
                and obs.captured_at <= audit_at
                and (audit_at - obs.observed_at).total_seconds() <= 3 * 86400
                for obs in observations
            )
            recent_link = any(
                obs.evidence_id.startswith("activity_")
                and obs.observed_at <= audit_at
                and obs.captured_at <= audit_at
                and (audit_at - obs.observed_at).total_seconds() <= 3 * 86400
                for obs in observations
            )
            # An event may have occurred before the audit cutoff but only be
            # exported/captured later. It cannot prove the historical state
            # (latest_state enforces captured_at <= audit_at), but the known
            # resource still belongs in the forward verification plan when the
            # case is incomplete. Do not let observations that themselves
            # occurred after the cutoff expand the scope.
            known_before_cutoff = any(
                obs.observed_at <= audit_at and obs.captured_at > audit_at
                for obs in observations
            )
            if in_focus_file or near_audit or recent_link or rid in near_report_resources or known_before_cutoff:
                focused_resources.add(rid)
        resources = sorted(focused_resources)
        findings: list[dict[str, Any]] = []
        remediation: list[dict[str, Any]] = []
        verification_specs: list[tuple[str, str, str, str, Observation | None]] = []

        for resource_id in resources:
            observations = self.observations_by_resource.get(resource_id, [])
            representative = observations[0] if observations else None
            system = representative.system_id if representative else infer_system(resource_id)
            current = self.latest_state(resource_id, audit_at)
            category = (
                current.category
                if current is not None
                else representative.category
                if representative is not None
                else category_for(system, resource_id, {})
            )
            policy = resource_policy(resource_id, system, category)
            verification_specs.append(
                (policy["verification"], system, resource_id, policy["required"], current)
            )
            if current is None or current.state == policy["required"]:
                continue
            if not policy["finding"]:
                continue
            findings.append(
                {
                    "phase": "FINDING",
                    "system_id": system,
                    "resource_id": resource_id,
                    "operation": policy["finding"],
                    "state": "ACTIVE" if category in {"DISABLE", "BLOCK"} else "PRESENT",
                    "evidence_id": current.evidence_id,
                }
            )
            remediation.append(
                {
                    "phase": "REMEDIATION",
                    "system_id": system,
                    "resource_id": resource_id,
                    "operation": policy["remediation"],
                    "state": policy["required"],
                    "evidence_id": "",
                }
            )

        # Absence of findings is not proof of deletion when no resource has
        # any pre-cutoff verification evidence. Do not silently mark an
        # authorized request COMPLETE merely because discovery returned zero
        # resources; keep it INCOMPLETE until the subject's relevant systems
        # can be verified. We intentionally do not fabricate a resource ID or
        # evidence reference when none is available.
        has_verifiable_state = any(
            current is not None and current.state == required
            for _operation, _system, _resource_id, required, current in verification_specs
        )
        incomplete = bool(findings) or not has_verifiable_state
        findings.sort(
            key=lambda step: (
                FINDING_ORDER[step["operation"]], step["system_id"], step["resource_id"]
            )
        )
        remediation.sort(
            key=lambda step: (
                REMEDIATION_ORDER[step["operation"]], step["system_id"], step["resource_id"]
            )
        )

        verification: list[dict[str, Any]] = []
        for operation, system, resource_id, required, current in verification_specs:
            if incomplete:
                evidence_id = ""
            else:
                if current is None or current.state != required:
                    continue
                evidence_id = current.evidence_id
            verification.append(
                {
                    "phase": "VERIFICATION",
                    "system_id": system,
                    "resource_id": resource_id,
                    "operation": operation,
                    "state": required,
                    "evidence_id": evidence_id,
                }
            )
        verification.sort(
            key=lambda step: (
                VERIFICATION_ORDER[step["operation"]], step["system_id"], step["resource_id"]
            )
        )

        steps = findings + remediation + verification
        for index, step in enumerate(steps, start=1):
            step["step_no"] = index
        # Required object field order is not semantically significant, but use
        # the documented order for human readability.
        ordered_steps = [
            {
                "step_no": step["step_no"],
                "phase": step["phase"],
                "system_id": step["system_id"],
                "resource_id": step["resource_id"],
                "operation": step["operation"],
                "state": step["state"],
                "evidence_id": step["evidence_id"],
            }
            for step in steps
        ]
        return {
            "case_id": case_id,
            "deletion_status": "INCOMPLETE" if incomplete else "COMPLETE",
            "steps_json": json.dumps(ordered_steps, ensure_ascii=False, separators=(",", ":")),
        }


def numeric_case_key(row: dict[str, str]) -> tuple[int, str]:
    match = re.search(r"(\d+)$", row["case_id"])
    return (int(match.group(1)) if match else sys.maxsize, row["case_id"])


def write_output(rows: list[dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: row["case_id"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Process sample_deletion_requests.csv instead of the 518 evaluation requests.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path. Defaults to sample_prediction.csv for --sample, otherwise root output.csv.",
    )
    args = parser.parse_args()

    requests_path = DATASET / (
        "sample_deletion_requests.csv" if args.sample else "deletion_requests.csv"
    )
    output_path = args.output or (ROOT / ("sample_prediction.csv" if args.sample else "output.csv"))
    agent = AuditAgent(DATASET)
    predictions = [agent.audit_case(request) for request in read_csv(requests_path)]
    write_output(predictions, output_path)
    print(
        json.dumps(
            {
                "requests": len(predictions),
                "observations": len(agent.observations),
                "linked_users": len(agent.resources_by_user),
                "output": str(output_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
