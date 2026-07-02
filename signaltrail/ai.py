from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


DEFAULT_ENDPOINT = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = "gpt-5.5"

AI_INSTRUCTIONS = """You are SignalTrail's privacy audit analyst.
Analyze iPhone app network metadata for possible privacy violations.
Rules:
- Do not claim direct microphone, camera, GPS, contacts, Bluetooth, or photo access unless the evidence proves it.
- Treat sensor categories as leads inferred from network evidence.
- Separate evidence from interpretation.
- Focus on user-actionable debugging steps.
- Keep the report concise and practical."""


def generate_ai_analysis(report: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("SIGNALTRAIL_AI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return offline_analysis(report, note="No AI API key configured; using local rule-based analysis.")

    endpoint = os.getenv("SIGNALTRAIL_AI_ENDPOINT", DEFAULT_ENDPOINT)
    model = os.getenv("SIGNALTRAIL_AI_MODEL", DEFAULT_MODEL)
    payload = {
        "model": model,
        "instructions": AI_INSTRUCTIONS,
        "input": build_ai_prompt(report),
    }

    try:
        response = call_responses_api(endpoint, api_key, payload)
        text = extract_response_text(response)
        if not text:
            return offline_analysis(report, note="AI response had no text; using local rule-based analysis.")
        return {
            "provider": "openai_responses",
            "model": model,
            "summary": text,
            "prompt": build_ai_prompt(report),
            "used_cloud_ai": True,
        }
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        return offline_analysis(report, note=f"AI request failed: {exc}; using local rule-based analysis.")


def build_ai_prompt(report: dict[str, Any]) -> str:
    compact = {
        "event_count": report.get("event_count", 0),
        "recent_event_count": report.get("recent_event_count", 0),
        "privacy_audit": report.get("privacy_audit", {}),
        "top_domains": report.get("top_domains", [])[:20],
        "findings": report.get("findings", [])[:30],
    }
    return (
        "Review this SignalTrail privacy audit JSON. Identify likely privacy risks, "
        "possible sensor-related behavior, evidence strength, and next debugging steps.\n\n"
        f"{json.dumps(compact, indent=2, sort_keys=True)}"
    )


def call_responses_api(endpoint: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_response_text(response: dict[str, Any]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str):
        return direct.strip()

    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return "\n".join(chunks).strip()


def offline_analysis(report: dict[str, Any], note: str | None = None) -> dict[str, Any]:
    audit = report.get("privacy_audit", {})
    summary = audit.get("summary", {})
    signals = audit.get("signals", [])
    top_domains = report.get("top_domains", [])

    lines = [
        f"Privacy risk is {summary.get('risk_label', 'none')} with score {summary.get('risk_score', 0)}/100.",
        f"Observed {report.get('event_count', 0)} network events across {len(top_domains)} top domains.",
    ]
    sensor_count = summary.get("sensor_signal_count", 0)
    if sensor_count:
        lines.append(f"Found {sensor_count} possible sensor-related signal(s). Treat these as inferred leads.")

    important = sorted(signals, key=lambda item: risk_rank(str(item.get("risk", ""))))[:5]
    if important:
        lines.append("Top evidence:")
        for signal in important:
            lines.append(
                f"- {signal.get('risk', 'unknown').upper()} {signal.get('title')}: {signal.get('evidence')}"
            )
    else:
        lines.append("No privacy signals yet. Capture traffic while opening one target app, then repeat while idle.")

    lines.append("Next steps: compare idle vs active runs, investigate high-risk domains, and verify app permissions on iOS.")

    return {
        "provider": "offline_rules",
        "model": None,
        "summary": "\n".join(lines),
        "prompt": build_ai_prompt(report),
        "used_cloud_ai": False,
        "note": note,
    }


def risk_rank(risk: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(risk, 9)
