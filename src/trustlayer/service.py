from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .audit import AuditStore
from .policy import DetectorRule, PolicyConfig, PolicySnapshot, PolicyStore
from .sanitizer import VisibleTextExtractor


@dataclass(frozen=True)
class DecisionResult:
    request_id: str
    decision: str
    risk_flags: list[str]
    payload: dict[str, Any]
    matched_policies: list[str]


class DefenseGatewayService:
    def __init__(
        self,
        audit_store: AuditStore,
        policy: PolicyConfig | None = None,
        policy_store: PolicyStore | None = None,
    ) -> None:
        self.audit = audit_store
        self.policy_store = policy_store or PolicyStore(audit_store.db_path)
        if policy is not None:
            self.policy_store.apply_config(policy)

    def sanitize_ingress(
        self,
        *,
        tenant_id: str,
        session_id: str,
        source_type: str,
        origin: str,
        content: str,
        request_id: str | None = None,
        audit_metadata: dict[str, Any] | None = None,
    ) -> DecisionResult:
        request_id = request_id or self._request_id()
        snapshot = self.policy_store.snapshot()
        source_policy = snapshot.source_policy_for(source_type)

        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="source_received",
            summary=f"Received {source_type} from {origin}",
            metadata=self._merge_audit_metadata(
                {"source_type": source_type, "origin": origin},
                audit_metadata,
            ),
        )

        visible_text, removed_regions = self._sanitize_content(source_policy.extractor_kind, content)
        risk_flags, matched_policies = self._evaluate_ingress_rules(
            snapshot=snapshot,
            source_type=source_type,
            raw_content=content,
            visible_text=visible_text,
            removed_regions=removed_regions,
        )

        default_policy_id = str(snapshot.setting("ingress_default_policy_id", ""))
        if default_policy_id:
            matched_policies = [default_policy_id, *matched_policies]

        max_visible_excerpt = int(snapshot.setting("max_visible_excerpt", len(visible_text) or 0))
        payload = {
            "source": {
                "type": source_type,
                "origin": origin,
                "trust_level": source_policy.trust_level,
            },
            "content": {
                "visible_excerpt": visible_text[:max_visible_excerpt],
                "selected_chunks": self._chunk_text(visible_text, snapshot),
                "removed_regions": removed_regions,
            },
        }
        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="policy_matched",
            decision=str(snapshot.setting("ingress_default_decision", "allow_sanitized")),
            policy_id=default_policy_id or None,
            summary="Ingress sanitized by policy store",
            metadata=self._merge_audit_metadata(
                {"matched_policies": matched_policies},
                audit_metadata,
            ),
        )
        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="source_sanitized",
            decision=str(snapshot.setting("ingress_default_decision", "allow_sanitized")),
            summary=f"Sanitized {source_type}",
            metadata=self._merge_audit_metadata(
                {
                    "source_type": source_type,
                    "origin": origin,
                    "removed_regions": removed_regions,
                    "risk_flags": risk_flags,
                    "content_hash": self._hash(visible_text),
                },
                audit_metadata,
            ),
        )
        return DecisionResult(
            request_id=request_id,
            decision=str(snapshot.setting("ingress_default_decision", "allow_sanitized")),
            risk_flags=risk_flags,
            payload=payload,
            matched_policies=matched_policies,
        )

    def check_egress(
        self,
        *,
        tenant_id: str,
        session_id: str,
        destination: str,
        destination_type: str,
        payload: str,
        request_id: str | None = None,
        audit_metadata: dict[str, Any] | None = None,
    ) -> DecisionResult:
        request_id = request_id or self._request_id()
        snapshot = self.policy_store.snapshot()
        destination_host = (urlparse(destination).hostname or destination).lower()
        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="egress_attempted",
            summary=f"Attempted egress to {destination_host}",
            metadata=self._merge_audit_metadata(
                {
                    "destination": destination,
                    "destination_host": destination_host,
                    "destination_type": destination_type,
                },
                audit_metadata,
            ),
        )

        context = {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "destination": destination,
            "destination_host": destination_host,
            "destination_type": destination_type,
            "payload": payload,
        }
        risk_flags, matched_policies, triggered_rules = self._evaluate_egress_rules(snapshot, context)

        for rule in triggered_rules:
            if rule.event_type:
                summary = rule.summary_template.format(**context) if rule.summary_template else f"Matched {rule.rule_id}"
                self.audit.append_event(
                    session_id=session_id,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    event_type=rule.event_type,
                    summary=summary,
                    metadata=self._merge_audit_metadata(
                        {"destination_host": destination_host},
                        audit_metadata,
                    ),
                )

        decision_rule = snapshot.decision_rule_for("egress", risk_flags)
        decision = decision_rule.decision

        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="egress_scanned",
            decision=decision,
            summary="Egress payload scanned",
            metadata=self._merge_audit_metadata(
                {
                    "risk_flags": risk_flags,
                    "destination_host": destination_host,
                    "content_hash": self._hash(payload),
                },
                audit_metadata,
            ),
        )
        for policy_id in matched_policies:
            self.audit.append_event(
                session_id=session_id,
                request_id=request_id,
                tenant_id=tenant_id,
                event_type="policy_matched",
                decision=decision,
                policy_id=policy_id,
                summary=f"Matched {policy_id}",
                metadata=self._merge_audit_metadata(
                    {"destination_host": destination_host},
                    audit_metadata,
                ),
            )

        approval_summary = self._approval_summary(
            snapshot=snapshot,
            decision=decision,
            destination_host=destination_host,
            risk_flags=risk_flags,
        )
        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type=decision_rule.event_type,
            decision=decision,
            summary=f"Egress decision: {decision}",
            metadata=self._merge_audit_metadata(
                {
                    "destination_host": destination_host,
                    "risk_flags": risk_flags,
                    "approval_summary": approval_summary,
                },
                audit_metadata,
            ),
        )
        return DecisionResult(
            request_id=request_id,
            decision=decision,
            risk_flags=risk_flags,
            payload={
                "destination": destination,
                "destination_type": destination_type,
                "approval_summary": approval_summary,
            },
            matched_policies=matched_policies,
        )

    def timeline(self, session_id: str) -> list[dict[str, Any]]:
        return [
            {
                "event_id": event.event_id,
                "request_id": event.request_id,
                "event_type": event.event_type,
                "decision": event.decision,
                "policy_id": event.policy_id,
                "summary": event.summary,
                "metadata": event.metadata,
                "created_at": event.created_at,
            }
            for event in self.audit.timeline(session_id)
        ]

    def approval_queue(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
        snapshot = self.policy_store.snapshot()
        priority = {
            str(key): int(value)
            for key, value in dict(snapshot.setting("approval_priority", {})).items()
        }
        event_types = [str(item) for item in snapshot.setting("approval_event_types", [])]
        return self.audit.approval_queue(
            tenant_id,
            event_types=event_types,
            priority=priority,
            limit=limit,
        )

    def _sanitize_content(self, extractor_kind: str, content: str) -> tuple[str, list[str]]:
        if extractor_kind == "visible_text":
            extractor = VisibleTextExtractor()
            return extractor.extract(content)
        return self._normalize_text(content), []

    def _evaluate_ingress_rules(
        self,
        *,
        snapshot: PolicySnapshot,
        source_type: str,
        raw_content: str,
        visible_text: str,
        removed_regions: list[str],
    ) -> tuple[list[str], list[str]]:
        source_policy = snapshot.source_policy_for(source_type)
        flags = list(source_policy.static_risk_flags)
        matched_policies: list[str] = []
        context = {
            "source_type": source_type,
            "raw_content": raw_content,
            "visible_text": visible_text,
            "removed_regions": removed_regions,
        }
        for rule in snapshot.detector_rules_for("ingress"):
            if self._rule_matches(rule, context, snapshot):
                flags.append(rule.flag_name)
                matched_policies.append(rule.policy_id)
        return sorted(set(flags)), self._dedupe(matched_policies)

    def _evaluate_egress_rules(
        self,
        snapshot: PolicySnapshot,
        context: dict[str, Any],
    ) -> tuple[list[str], list[str], list[DetectorRule]]:
        flags: list[str] = []
        matched_policies: list[str] = []
        triggered_rules: list[DetectorRule] = []
        for rule in snapshot.detector_rules_for("egress"):
            if self._rule_matches(rule, context, snapshot):
                flags.append(rule.flag_name)
                matched_policies.append(rule.policy_id)
                triggered_rules.append(rule)
        return sorted(set(flags)), self._dedupe(matched_policies), triggered_rules

    def _rule_matches(
        self,
        rule: DetectorRule,
        context: dict[str, Any],
        snapshot: PolicySnapshot,
    ) -> bool:
        if rule.detector_kind == "removed_region_present":
            return bool(context.get("removed_regions"))
        if rule.detector_kind == "text_length_over_threshold":
            target_value = str(context.get(rule.target or "", ""))
            threshold = int(snapshot.setting(str(rule.threshold_setting), 0))
            return len(target_value) > threshold
        if rule.detector_kind == "source_type_equals":
            return str(context.get("source_type")) == str(rule.expected_value)
        if rule.detector_kind == "regex":
            target_value = str(context.get(rule.target or "", ""))
            return bool(re.search(str(rule.pattern), target_value))
        if rule.detector_kind == "new_destination_host":
            destination_host = str(context.get("destination_host", "")).lower()
            allowed_hosts = {
                str(host).lower()
                for host in snapshot.setting("allowed_destination_hosts", [])
            }
            if destination_host in allowed_hosts:
                return False
            seen_event_types = [str(item) for item in snapshot.setting("seen_destination_event_types", [])]
            return not self.audit.has_seen_destination(
                str(context["tenant_id"]),
                destination_host,
                event_types=seen_event_types,
            )
        raise KeyError(f"unsupported_detector_kind:{rule.detector_kind}")

    def _chunk_text(self, text: str, snapshot: PolicySnapshot) -> list[str]:
        normalized = self._normalize_text(text)
        if not normalized:
            return []
        max_chunk_size = int(snapshot.setting("max_chunk_size", len(normalized)))
        max_chunks = int(snapshot.setting("max_chunks", 1))
        chunks = [
            normalized[i : i + max_chunk_size]
            for i in range(0, len(normalized), max_chunk_size)
        ]
        return chunks[:max_chunks]

    def _normalize_text(self, value: str) -> str:
        return " ".join(value.split())

    def _hash(self, payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _request_id(self) -> str:
        return f"req_{uuid.uuid4().hex[:12]}"

    def _approval_summary(
        self,
        *,
        snapshot: PolicySnapshot,
        decision: str,
        destination_host: str,
        risk_flags: list[str],
    ) -> str:
        if decision == "allow":
            return f"Allowed outbound request to {destination_host}."

        reasons: list[str] = []
        for flag in risk_flags:
            text = snapshot.approval_reason(flag)
            if text:
                reasons.append(text)

        reason_text = ", ".join(reasons) if reasons else "risk conditions matched"
        prefix = "Blocked" if decision == "block" else "Review required"
        return f"{prefix}: outbound request to {destination_host} {reason_text}."

    def _merge_audit_metadata(
        self,
        base: dict[str, Any],
        extra: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if not extra:
            return base
        merged = dict(extra)
        merged.update(base)
        return merged

    def _dedupe(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered
