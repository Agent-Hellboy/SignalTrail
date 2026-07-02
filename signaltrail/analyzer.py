from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from time import time
from typing import Any


TRACKER_HINTS = (
    "doubleclick.",
    "googlesyndication.",
    "google-analytics.",
    "app-measurement.",
    "firebase-settings.",
    "facebook.com/tr",
    "graph.facebook.com",
    "analytics",
    "amplitude.",
    "segment.",
    "mixpanel.",
    "branch.io",
    "adjust.",
    "appsflyer.",
    "crashlytics.",
)

SENSOR_HINTS = {
    "possible_location": (
        "location",
        "geolocation",
        "gps",
        "lat=",
        "latitude",
        "lng=",
        "longitude",
        "nearby",
        "places",
    ),
    "possible_audio": (
        "audio",
        "voice",
        "microphone",
        "speech",
        "transcribe",
        "transcription",
        "recording",
    ),
    "possible_camera_or_photos": (
        "camera",
        "photo",
        "image",
        "media/upload",
        "vision",
        "ocr",
    ),
    "possible_contacts": (
        "contacts",
        "addressbook",
        "friends/import",
        "contact-sync",
    ),
    "possible_bluetooth_or_nearby": (
        "bluetooth",
        "ble",
        "beacon",
        "nearby-devices",
    ),
}


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    evidence: str
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "domain": self.domain,
        }


@dataclass(frozen=True)
class PrivacySignal:
    category: str
    risk: str
    confidence: str
    title: str
    evidence: str
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "risk": self.risk,
            "confidence": self.confidence,
            "title": self.title,
            "evidence": self.evidence,
            "domain": self.domain,
        }


def classify_domain(host: str, path: str = "") -> list[str]:
    needle = f"{host}{path}".lower()
    tags: list[str] = []
    if any(hint in needle for hint in TRACKER_HINTS):
        tags.append("tracker_or_analytics")
    if any(part in needle for part in ("ads", "adservice", "advertising")):
        tags.append("adtech")
    if any(part in needle for part in ("telemetry", "metrics", "events", "beacon")):
        tags.append("telemetry")
    for tag, hints in SENSOR_HINTS.items():
        if any(hint in needle for hint in hints):
            tags.append(tag)
    return tags


def analyze_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    now = time()
    by_domain: Counter[str] = Counter()
    bytes_by_domain: Counter[str] = Counter()
    tags_by_domain: dict[str, set[str]] = defaultdict(set)
    findings: list[Finding] = []
    privacy_signals: list[PrivacySignal] = []

    recent = [event for event in events if now - float(event.get("started_at", now)) <= 600]

    for event in events:
        host = str(event.get("host") or "unknown")
        path = str(event.get("path") or "")
        by_domain[host] += 1
        bytes_by_domain[host] += int(event.get("bytes_client_to_server", 0))
        bytes_by_domain[host] += int(event.get("bytes_server_to_client", 0))
        for tag in classify_domain(host, path):
            tags_by_domain[host].add(tag)

        if event.get("scheme") == "http":
            findings.append(
                Finding(
                    "medium",
                    "Plaintext HTTP request",
                    f"{event.get('method', 'HTTP')} {host}{path}",
                    host,
                )
            )
            privacy_signals.append(
                PrivacySignal(
                    "data_exposure",
                    "medium",
                    "high",
                    "Plaintext HTTP traffic",
                    f"{event.get('method', 'HTTP')} {host}{path} was sent without HTTPS.",
                    host,
                )
            )

        privacy_signals.extend(sensor_signals_for_event(event, host, path))

    for host, tags in tags_by_domain.items():
        if "tracker_or_analytics" in tags or "adtech" in tags:
            findings.append(
                Finding(
                    "low",
                    "Tracker or analytics-looking domain",
                    f"{host} matched tags: {', '.join(sorted(tags))}",
                    host,
                )
            )
            privacy_signals.append(
                PrivacySignal(
                    "tracking",
                    "low",
                    "medium",
                    "Tracker or analytics endpoint",
                    f"{host} matched tags: {', '.join(sorted(tags))}",
                    host,
                )
            )
        sensor_tags = sorted(tag for tag in tags if tag.startswith("possible_"))
        if sensor_tags:
            findings.append(
                Finding(
                    "low",
                    "Possible sensor-related network traffic",
                    f"{host} matched tags: {', '.join(sensor_tags)}. This is an inference from URL/domain text, not direct iOS sensor access.",
                    host,
                )
            )

    for host, total in bytes_by_domain.most_common(10):
        if total >= 5_000_000:
            findings.append(
                Finding(
                    "medium",
                    "High traffic volume",
                    f"{host} transferred about {format_bytes(total)} in this session.",
                    host,
                )
            )
            privacy_signals.append(
                PrivacySignal(
                    "data_volume",
                    "medium",
                    "medium",
                    "High data transfer",
                    f"{host} transferred about {format_bytes(total)} in this session.",
                    host,
                )
            )

    recent_counts = Counter(str(event.get("host") or "unknown") for event in recent)
    for host, count in recent_counts.most_common():
        if count >= 20:
            findings.append(
                Finding(
                    "low",
                    "Repeated recent background chatter",
                    f"{host} appeared {count} times in the last 10 minutes.",
                    host,
                )
            )
            privacy_signals.append(
                PrivacySignal(
                    "background_activity",
                    "low",
                    "medium",
                    "Repeated recent network activity",
                    f"{host} appeared {count} times in the last 10 minutes.",
                    host,
                )
            )

    return {
        "generated_at": now,
        "event_count": len(events),
        "recent_event_count": len(recent),
        "privacy_audit": build_privacy_audit(privacy_signals),
        "top_domains": [
            {
                "domain": host,
                "requests": count,
                "bytes": bytes_by_domain[host],
                "tags": sorted(tags_by_domain.get(host, set())),
            }
            for host, count in by_domain.most_common(20)
        ],
        "findings": [finding.to_dict() for finding in dedupe_findings(findings)],
    }


def sensor_signals_for_event(event: dict[str, Any], host: str, path: str) -> list[PrivacySignal]:
    tags = classify_domain(host, path)
    signals: list[PrivacySignal] = []
    has_visible_path = bool(path)
    scheme = str(event.get("scheme") or "")
    for tag in tags:
        if not tag.startswith("possible_"):
            continue
        category = tag.removeprefix("possible_")
        confidence = "medium" if has_visible_path else "low"
        risk = "high" if scheme == "http" and has_visible_path else "medium"
        evidence = f"{host}{path} matched {tag}"
        if not has_visible_path:
            evidence += "; HTTPS tunnel hides URL path, so this is domain-only evidence"
        signals.append(
            PrivacySignal(
                f"sensor_{category}",
                risk,
                confidence,
                f"Possible {category.replace('_', ' ')} usage",
                evidence,
                host,
            )
        )
    return signals


def build_privacy_audit(signals: list[PrivacySignal]) -> dict[str, Any]:
    deduped = dedupe_privacy_signals(signals)
    by_category: dict[str, list[PrivacySignal]] = defaultdict(list)
    for signal in deduped:
        by_category[signal.category].append(signal)

    return {
        "summary": summarize_privacy_risk(deduped),
        "categories": [
            {
                "category": category,
                "signal_count": len(items),
                "highest_risk": highest_risk(items),
                "highest_confidence": highest_confidence(items),
            }
            for category, items in sorted(by_category.items())
        ],
        "signals": [signal.to_dict() for signal in deduped],
    }


def summarize_privacy_risk(signals: list[PrivacySignal]) -> dict[str, Any]:
    risk_score = 0
    risk_weight = {"high": 30, "medium": 15, "low": 5}
    confidence_weight = {"high": 1.0, "medium": 0.75, "low": 0.4}
    for signal in signals:
        risk_score += int(risk_weight.get(signal.risk, 0) * confidence_weight.get(signal.confidence, 0.5))
    risk_score = min(risk_score, 100)
    if risk_score >= 70:
        label = "high"
    elif risk_score >= 35:
        label = "medium"
    elif risk_score > 0:
        label = "low"
    else:
        label = "none"
    return {
        "risk_score": risk_score,
        "risk_label": label,
        "signal_count": len(signals),
        "sensor_signal_count": sum(1 for signal in signals if signal.category.startswith("sensor_")),
    }


def highest_risk(signals: list[PrivacySignal]) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    return max((signal.risk for signal in signals), key=lambda value: order.get(value, 0), default="none")


def highest_confidence(signals: list[PrivacySignal]) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    return max((signal.confidence for signal in signals), key=lambda value: order.get(value, 0), default="none")


def dedupe_privacy_signals(signals: list[PrivacySignal]) -> list[PrivacySignal]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[PrivacySignal] = []
    for signal in signals:
        key = (signal.category, signal.title, signal.domain)
        if key not in seen:
            seen.add(key)
            result.append(signal)
    risk_order = {"high": 0, "medium": 1, "low": 2}
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(result, key=lambda item: (risk_order.get(item.risk, 9), confidence_order.get(item.confidence, 9)))


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.severity, finding.title, finding.domain)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(result, key=lambda item: order.get(item.severity, 9))


def format_bytes(value: int) -> str:
    units = ("B", "KB", "MB", "GB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"
