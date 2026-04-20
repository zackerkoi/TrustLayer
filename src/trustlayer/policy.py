from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_POLICY_FILE = Path(__file__).resolve().parents[2] / "config" / "policy.example.json"


@dataclass(frozen=True)
class PolicyConfig:
    ingress_oversized_threshold: int | None = None
    egress_oversized_threshold: int | None = None
    allowed_destination_hosts: set[str] = field(default_factory=set)
    document: dict[str, Any] | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if "settings" in payload or "source_policies" in payload or "detector_rules" in payload:
            return cls(document=payload)
        return cls(
            ingress_oversized_threshold=payload.get("ingress_oversized_threshold"),
            egress_oversized_threshold=payload.get("egress_oversized_threshold"),
            allowed_destination_hosts={
                host.lower() for host in payload.get("allowed_destination_hosts", [])
            },
        )

    def to_document(self) -> dict[str, Any]:
        if self.document is not None:
            return self.document

        settings: dict[str, Any] = {}
        if self.ingress_oversized_threshold is not None:
            settings["ingress_oversized_threshold"] = self.ingress_oversized_threshold
        if self.egress_oversized_threshold is not None:
            settings["egress_oversized_threshold"] = self.egress_oversized_threshold
        if self.allowed_destination_hosts:
            settings["allowed_destination_hosts"] = sorted(self.allowed_destination_hosts)
        return {"settings": settings}


@dataclass(frozen=True)
class SourcePolicy:
    source_type: str
    trust_level: str
    extractor_kind: str
    static_risk_flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectorRule:
    rule_id: str
    direction: str
    detector_kind: str
    flag_name: str
    policy_id: str
    decision: str | None = None
    pattern: str | None = None
    target: str | None = None
    expected_value: str | None = None
    threshold_setting: str | None = None
    summary_template: str | None = None
    event_type: str | None = None
    enabled: bool = True


@dataclass(frozen=True)
class DecisionRule:
    rule_id: str
    direction: str
    decision: str
    event_type: str
    when_any_flags: tuple[str, ...] = ()
    priority: int = 100
    default_rule: bool = False


@dataclass(frozen=True)
class PolicySnapshot:
    settings: dict[str, Any]
    source_policies: dict[str, SourcePolicy]
    detector_rules: tuple[DetectorRule, ...]
    decision_rules: tuple[DecisionRule, ...]
    approval_summary_rules: dict[str, str]

    def setting(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)

    def source_policy_for(self, source_type: str) -> SourcePolicy:
        return self.source_policies.get(source_type) or self.source_policies["__default__"]

    def detector_rules_for(self, direction: str) -> tuple[DetectorRule, ...]:
        return tuple(rule for rule in self.detector_rules if rule.direction == direction and rule.enabled)

    def decision_rule_for(self, direction: str, flags: list[str]) -> DecisionRule:
        flag_set = set(flags)
        candidates = [rule for rule in self.decision_rules if rule.direction == direction]
        for rule in candidates:
            if rule.when_any_flags and flag_set.intersection(rule.when_any_flags):
                return rule
        for rule in candidates:
            if rule.default_rule:
                return rule
        raise KeyError(f"missing_default_decision_rule:{direction}")

    def approval_reason(self, flag_name: str) -> str | None:
        return self.approval_summary_rules.get(flag_name)


class PolicyStore:
    def __init__(
        self,
        db_path: str | Path,
        *,
        seed_file: str | Path | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.seed_file = str(seed_file or DEFAULT_POLICY_FILE)
        self._memory_conn: sqlite3.Connection | None = None
        self._init_db()
        self._seed_if_empty()

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(self.db_path)
                self._memory_conn.row_factory = sqlite3.Row
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS source_policies (
                    source_type TEXT PRIMARY KEY,
                    trust_level TEXT NOT NULL,
                    extractor_kind TEXT NOT NULL,
                    static_risk_flags_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS detector_rules (
                    rule_id TEXT PRIMARY KEY,
                    direction TEXT NOT NULL,
                    detector_kind TEXT NOT NULL,
                    flag_name TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    decision TEXT,
                    pattern TEXT,
                    target TEXT,
                    expected_value TEXT,
                    threshold_setting TEXT,
                    summary_template TEXT,
                    event_type TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS decision_rules (
                    rule_id TEXT PRIMARY KEY,
                    direction TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    when_any_flags_json TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 100,
                    default_rule INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_summary_rules (
                    flag_name TEXT PRIMARY KEY,
                    text TEXT NOT NULL
                )
                """
            )

    def _seed_if_empty(self) -> None:
        with self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM policy_settings").fetchone()[0]
        if count:
            return
        self.import_document(json.loads(Path(self.seed_file).read_text(encoding="utf-8")))

    def import_document(self, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM policy_settings")
            conn.execute("DELETE FROM source_policies")
            conn.execute("DELETE FROM detector_rules")
            conn.execute("DELETE FROM decision_rules")
            conn.execute("DELETE FROM approval_summary_rules")

            for key, value in payload.get("settings", {}).items():
                conn.execute(
                    "INSERT INTO policy_settings (key, value_json) VALUES (?, ?)",
                    (key, json.dumps(value, ensure_ascii=True, sort_keys=True)),
                )

            for item in payload.get("source_policies", []):
                conn.execute(
                    """
                    INSERT INTO source_policies (
                        source_type, trust_level, extractor_kind, static_risk_flags_json
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        item["source_type"],
                        item["trust_level"],
                        item["extractor_kind"],
                        json.dumps(item.get("static_risk_flags", []), ensure_ascii=True, sort_keys=True),
                    ),
                )

            for item in payload.get("detector_rules", []):
                conn.execute(
                    """
                    INSERT INTO detector_rules (
                        rule_id, direction, detector_kind, flag_name, policy_id, decision,
                        pattern, target, expected_value, threshold_setting,
                        summary_template, event_type, enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["rule_id"],
                        item["direction"],
                        item["detector_kind"],
                        item["flag_name"],
                        item["policy_id"],
                        item.get("decision"),
                        item.get("pattern"),
                        item.get("target"),
                        item.get("expected_value"),
                        item.get("threshold_setting"),
                        item.get("summary_template"),
                        item.get("event_type"),
                        1 if item.get("enabled", True) else 0,
                    ),
                )

            for item in payload.get("decision_rules", []):
                conn.execute(
                    """
                    INSERT INTO decision_rules (
                        rule_id, direction, decision, event_type, when_any_flags_json, priority, default_rule
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["rule_id"],
                        item["direction"],
                        item["decision"],
                        item["event_type"],
                        json.dumps(item.get("when_any_flags", []), ensure_ascii=True, sort_keys=True),
                        int(item.get("priority", 100)),
                        1 if item.get("default_rule", False) else 0,
                    ),
                )

            for flag_name, text in payload.get("approval_summary_rules", {}).items():
                conn.execute(
                    "INSERT INTO approval_summary_rules (flag_name, text) VALUES (?, ?)",
                    (flag_name, text),
                )

    def apply_config(self, config: PolicyConfig) -> None:
        document = config.to_document()
        if any(key in document for key in ("source_policies", "detector_rules", "decision_rules", "approval_summary_rules")):
            self.import_document(document)
            return
        if not document.get("settings"):
            return
        with self._connect() as conn:
            for key, value in document["settings"].items():
                conn.execute(
                    """
                    INSERT INTO policy_settings (key, value_json)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
                    """,
                    (key, json.dumps(value, ensure_ascii=True, sort_keys=True)),
                )

    def snapshot(self) -> PolicySnapshot:
        with self._connect() as conn:
            setting_rows = conn.execute(
                "SELECT key, value_json FROM policy_settings ORDER BY key ASC"
            ).fetchall()
            source_rows = conn.execute(
                """
                SELECT source_type, trust_level, extractor_kind, static_risk_flags_json
                FROM source_policies
                ORDER BY source_type ASC
                """
            ).fetchall()
            detector_rows = conn.execute(
                """
                SELECT rule_id, direction, detector_kind, flag_name, policy_id, decision,
                       pattern, target, expected_value, threshold_setting,
                       summary_template, event_type, enabled
                FROM detector_rules
                ORDER BY rowid ASC
                """
            ).fetchall()
            decision_rows = conn.execute(
                """
                SELECT rule_id, direction, decision, event_type, when_any_flags_json, priority, default_rule
                FROM decision_rules
                ORDER BY priority ASC, rowid ASC
                """
            ).fetchall()
            summary_rows = conn.execute(
                "SELECT flag_name, text FROM approval_summary_rules ORDER BY flag_name ASC"
            ).fetchall()

        settings = {row["key"]: json.loads(row["value_json"]) for row in setting_rows}
        source_policies = {
            row["source_type"]: SourcePolicy(
                source_type=row["source_type"],
                trust_level=row["trust_level"],
                extractor_kind=row["extractor_kind"],
                static_risk_flags=tuple(json.loads(row["static_risk_flags_json"])),
            )
            for row in source_rows
        }
        detector_rules = tuple(
            DetectorRule(
                rule_id=row["rule_id"],
                direction=row["direction"],
                detector_kind=row["detector_kind"],
                flag_name=row["flag_name"],
                policy_id=row["policy_id"],
                decision=row["decision"],
                pattern=row["pattern"],
                target=row["target"],
                expected_value=row["expected_value"],
                threshold_setting=row["threshold_setting"],
                summary_template=row["summary_template"],
                event_type=row["event_type"],
                enabled=bool(row["enabled"]),
            )
            for row in detector_rows
        )
        decision_rules = tuple(
            DecisionRule(
                rule_id=row["rule_id"],
                direction=row["direction"],
                decision=row["decision"],
                event_type=row["event_type"],
                when_any_flags=tuple(json.loads(row["when_any_flags_json"])),
                priority=int(row["priority"]),
                default_rule=bool(row["default_rule"]),
            )
            for row in decision_rows
        )
        approval_summary_rules = {row["flag_name"]: row["text"] for row in summary_rows}
        return PolicySnapshot(
            settings=settings,
            source_policies=source_policies,
            detector_rules=detector_rules,
            decision_rules=decision_rules,
            approval_summary_rules=approval_summary_rules,
        )
