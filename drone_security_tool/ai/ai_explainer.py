"""
AI-powered explanation generator using Ollama (local, free, no API key needed).

Calls llama3.2 via the Ollama HTTP API to produce a plain-English explanation
of drone security scan results for non-technical users.

Setup:
    1. Install Ollama from https://ollama.com
    2. Run: ollama pull llama3.2
    3. Ollama starts automatically — no configuration needed.
"""
from __future__ import annotations

import json
from typing import Optional

import requests

from ai.vulnerability_engine import AnalysisReport
from scanner.fingerprint import DroneFingerprint
from tests.safe_tests import SafeTestResults
from utils.helpers import LOGGER

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"
FALLBACK_MESSAGE = (
    "AI explanation unavailable \u2014 Ollama is not running. "
    "Install from https://ollama.com then run: ollama pull llama3.2"
)


def _build_prompt(
    fingerprint: DroneFingerprint,
    analysis: AnalysisReport,
    tests: Optional[SafeTestResults],
) -> str:
    """Compose the prompt sent to the model with full scan data."""
    vuln_lines = []
    for f in analysis.vulnerabilities:
        vuln_lines.append(
            f"- {f.title} [Severity: {f.severity}, "
            f"Attack Feasibility: {f.attack_feasibility}]: {f.explanation}"
        )
    vulns_text = "\n".join(vuln_lines) if vuln_lines else "None detected."

    ports_text = ", ".join(str(p) for p in fingerprint.open_ports) or "None"

    if analysis.ml_available and analysis.ml_prediction:
        ml_text = (
            f"ML Prediction: {analysis.ml_prediction} "
            f"(confidence: {analysis.ml_confidence:.1%})"
        )
    else:
        ml_text = "ML model not available; using rule-based scoring."

    test_text = "Not performed."
    if tests and tests.ping:
        test_text = (
            f"Ping success: {tests.ping.success}, "
            f"Packet loss: {tests.ping.packet_loss or 'n/a'}%, "
            f"Latency: {(tests.latency.average_ms or 0):.1f} ms, "
            f"Diagnostic packet: {'OK' if tests.packet.success else 'Failed'}"
        )

    feasibility_lines = [
        f"- {f.title}: {f.attack_feasibility}"
        for f in analysis.vulnerabilities
    ]
    feasibility_text = "\n".join(feasibility_lines) if feasibility_lines else "N/A"

    return f"""\
You are a cybersecurity analyst writing for a non-technical audience.
Below are the results of a drone security scan. Write a clear, plain-English
explanation that includes:

1. A simple summary of how dangerous the situation is (use the risk score as a guide).
2. What each major vulnerability actually means in plain words.
3. The top 2-3 things the user should do right now.
4. An overall conclusion.

Keep the language friendly and avoid jargon. Use short paragraphs.

--- SCAN DATA ---
Risk Score: {analysis.risk_score}/100
{ml_text}

Open Ports: {ports_text}

Vulnerabilities:
{vulns_text}

Ping / Connectivity Results:
{test_text}

Attack Feasibility Ratings:
{feasibility_text}

Drone Fingerprint:
{fingerprint.summary()}
--- END SCAN DATA ---

Write the explanation now."""


def generate_ai_explanation(
    fingerprint: DroneFingerprint,
    analysis: AnalysisReport,
    tests: Optional[SafeTestResults],
    api_key: Optional[str] = None,  # unused — kept for interface compatibility
) -> str:
    """Return a plain-English AI explanation of the scan results.

    Calls llama3.2 via the local Ollama server. No API key or internet
    connection required. Returns a graceful fallback on any failure.
    """
    prompt = _build_prompt(fingerprint, analysis, tests)

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=120,  # local models can be slow on first run
        )
        response.raise_for_status()
        return response.json()["response"]
    except requests.exceptions.ConnectionError:
        LOGGER.warning("Ollama not reachable at %s", OLLAMA_URL)
        return FALLBACK_MESSAGE
    except Exception as exc:
        LOGGER.error("Ollama call failed: %s", exc)
        return f"AI explanation unavailable \u2014 error: {exc}"
