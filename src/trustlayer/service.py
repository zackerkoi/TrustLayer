from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .audit import AuditStore
from .policy import PolicyConfig
from .sanitizer import VisibleTextExtractor


SECRET_PATTERNS = [
    re.compile(r"\bsk_(test|live)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{8,}\b"),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_PATTERN = re.compile(r"\b1[3-9]\d{9}\b")

MAX_VISIBLE_EXCERPT = 280
MAX_CHUNK_SIZE = 280
MAX_CHUNKS = 3


@dataclass(frozen=True)
class DecisionResult:
    request_id: str
    decision: str
    risk_flags: list[str]
    payload: dict[str, Any]
    matched_policies: list[str]


class DefenseGatewayService:
    def __init__(self, audit_store: AuditStore, policy: PolicyConfig | None = None) -> None:
        self.audit = audit_store
        self.policy = policy or PolicyConfig()

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

        visible_text, removed_regions = self._sanitize_content(source_type, content)
        risk_flags = self._ingress_risk_flags(source_type, removed_regions, content)
        matched_policies = ["ingress_default_allow_sanitized"]
        if "hidden_content" in risk_flags:
            matched_policies.append("ingress_hidden_content_tag")
        if "oversized_text" in risk_flags:
            matched_policies.append("ingress_oversized_trim")
        if "tool_output_untrusted" in risk_flags:
            matched_policies.append("ingress_tool_output_untrusted")

        payload = {
            "source": {
                "type": source_type,
                "origin": origin,
                "trust_level": "untrusted" if source_type != "internal" else "trusted",
            },
            "content": {
                "visible_excerpt": visible_text[:MAX_VISIBLE_EXCERPT],
                "selected_chunks": self._chunk_text(visible_text),
                "removed_regions": removed_regions,
            },
        }
        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="policy_matched",
            decision="allow_sanitized",
            policy_id=matched_policies[0],
            summary="Ingress sanitized by default policy",
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
            decision="allow_sanitized",
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
            decision="allow_sanitized",
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

        risk_flags: list[str] = []
        matched_policies: list[str] = []

        if self._contains_secret(payload):
            risk_flags.append("secret_detected")
            matched_policies.append("egress_secret_block")
        if self._contains_pii(payload):
            risk_flags.append("pii_detected")
            matched_policies.append("egress_pii_review")
        if len(payload) > self.policy.egress_oversized_threshold:
            risk_flags.append("payload_oversized")
            matched_policies.append("egress_large_payload_review")

        is_new_domain = (
            destination_host not in self.policy.allowed_destination_hosts
            and not self.audit.has_seen_destination(tenant_id, destination_host)
        )
        if is_new_domain:
            risk_flags.append("new_domain")
            matched_policies.append("egress_new_domain_review")
            self.audit.append_event(
                session_id=session_id,
                request_id=request_id,
                tenant_id=tenant_id,
                event_type="destination_new_domain",
                summary=f"First-time destination {destination_host}",
                metadata=self._merge_audit_metadata(
                    {"destination_host": destination_host},
                    audit_metadata,
                ),
            )

        decision = "allow"
        if "secret_detected" in risk_flags:
            decision = "block"
        elif any(flag in risk_flags for flag in ("pii_detected", "new_domain", "payload_oversized")):
            decision = "review_required"

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

        final_event = {
            "allow": "egress_allowed",
            "block": "egress_blocked",
            "review_required": "egress_review_required",
        }[decision]
        approval_summary = self._approval_summary(
            decision=decision,
            destination_host=destination_host,
            risk_flags=risk_flags,
        )
        self.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type=final_event,
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
        return self.audit.approval_queue(tenant_id, limit=limit)

    def _sanitize_content(self, source_type: str, content: str) -> tuple[str, list[str]]:
        if source_type in {"web_page", "email_html"}:
            extractor = VisibleTextExtractor()
            return extractor.extract(content)
        return self._normalize_text(content), []

    def _ingress_risk_flags(
        self,
        source_type: str,
        removed_regions: list[str],
        raw_content: str,
    ) -> list[str]:
        risk_flags: list[str] = ["external_origin"]
        if removed_regions:
            risk_flags.append("hidden_content")
        if len(raw_content) > self.policy.ingress_oversized_threshold:
            risk_flags.append("oversized_text")
        if source_type == "mcp_response":
            risk_flags.append("tool_output_untrusted")
        return sorted(set(risk_flags))

    def _chunk_text(self, text: str) -> list[str]:
        normalized = self._normalize_text(text)
        if not normalized:
            return []
        chunks = [
            normalized[i : i + MAX_CHUNK_SIZE]
            for i in range(0, len(normalized), MAX_CHUNK_SIZE)
        ]
        return chunks[:MAX_CHUNKS]

    def _normalize_text(self, value: str) -> str:
        return " ".join(value.split())

    def _contains_secret(self, payload: str) -> bool:
        return any(pattern.search(payload) for pattern in SECRET_PATTERNS)

    def _contains_pii(self, payload: str) -> bool:
        return bool(EMAIL_PATTERN.search(payload) or PHONE_PATTERN.search(payload))

    def _hash(self, payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _request_id(self) -> str:
        return f"req_{uuid.uuid4().hex[:12]}"

    def _approval_summary(
        self,
        *,
        decision: str,
        destination_host: str,
        risk_flags: list[str],
    ) -> str:
        if decision == "allow":
            return f"Allowed outbound request to {destination_host}."

        reasons: list[str] = []
        if "secret_detected" in risk_flags:
            reasons.append("contains secret material")
        if "pii_detected" in risk_flags:
            reasons.append("contains PII")
        if "new_domain" in risk_flags:
            reasons.append("targets a new destination")
        if "payload_oversized" in risk_flags:
            reasons.append("payload is oversized")

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
