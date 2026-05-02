"""Thin Groq wrapper for the two narrow LLM tasks.

The LLM is used ONLY for:
  1. Generating a plain-English explanation of why a risk ranks where it does.
     Inputs: the ranked-row evidence (asset, vuln, threat-intel, business
     service, scoring factors). Output: 2-3 sentence explanation.
  2. Summarizing the retrieved NIST 800-53 control in plain English.
     Inputs: the actual NIST control text (retrieved via RAG). Output:
     2-3 sentence summary grounded only in the provided text.

Both calls use temperature=0.2 to reduce variance. Both use system prompts
that explicitly forbid invention of facts not present in the input. If the
LLM call fails (network/auth/rate-limit), the system degrades to a
deterministic template-based explanation so the page still renders.
"""
from __future__ import annotations
import os
import logging
import json
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


def _client():
    """Lazy import + initialize Groq client. Returns None if key/lib missing."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq
        return Groq(api_key=api_key)
    except Exception as e:
        log.warning("Groq client init failed: %s", e)
        return None


def _chat(messages: list[dict], temperature: float = 0.2, max_tokens: int = 400) -> Optional[str]:
    c = _client()
    if c is None:
        return None
    try:
        resp = c.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        log.warning("Groq call failed: %s", e)
        return None


# ---------- Task 1: ranking explanation ----------

EXPLAIN_SYSTEM = """You are a senior cyber risk analyst preparing a board-level brief.
You must produce a 2-3 sentence plain-English explanation of why a specific risk
ranks where it does in the prioritized risk list.

STRICT RULES:
- Use ONLY the evidence provided in the user message. Do not introduce CVEs, asset
  names, threat actors, or business services that are not in the evidence.
- Do not say "this is critical" without specifying WHY (cite the evidence: internet
  exposure, ransomware-tagged campaign, business service criticality, missing EDR,
  etc.).
- Be specific and evidence-backed. Use the asset name, the business service name,
  and the threat actor / campaign name when present.
- If the evidence contains 'also_affects' assets, briefly mention that the same CVE
  is present on those assets too - this widens the blast radius and is relevant to
  prioritization.
- Write for a technical manager. No marketing language. No bullet points in the
  output - return prose only.
- Maximum 70 words.
"""


def explain_ranking(rank: int, score: float, row: dict, factors: list[dict]) -> str:
    """Generate a plain-English explanation. Falls back to a template if LLM unavailable."""
    # Build a compact evidence dict
    evidence = {
        "rank": rank,
        "risk_score": round(float(score), 1),
        "asset": row.get("asset_name"),
        "asset_type": row.get("asset_type"),
        "environment": row.get("environment"),
        "internet_exposed": bool(row.get("internet_exposed_b") or row.get("internet_exposed_vuln_b")),
        "edr_installed": bool(row.get("edr_installed_b")),
        "vulnerability": row.get("vulnerability_name"),
        "cve": row.get("cve"),
        "cvss": row.get("cvss"),
        "exploit_available": bool(row.get("exploit_available_b")),
        "patch_available": bool(row.get("patch_available_b")),
        "days_open": row.get("days_open"),
        "kev_listed": bool(row.get("kev_listed", False)),
        "kev_ransomware_use": bool(row.get("kev_ransomware", False)),
        "business_service": row.get("business_service"),
        "business_revenue_impact": row.get("revenue_impact"),
        "customer_facing": row.get("customer_facing"),
        "compliance_scope": row.get("compliance_scope"),
        "threat_actor": row.get("threat_actor"),
        "campaign": row.get("campaign_name"),
        "ti_ransomware": bool(row.get("ti_any_ransomware", False)),
        "ti_target_region": row.get("target_region"),
        "ti_target_sector": row.get("target_sector"),
        "also_affects": row.get("also_affects") or [],
        "top_factors": [
            {"label": f["label"], "value": f["value"], "weight": f["weight"]}
            for f in sorted(factors, key=lambda x: -x["contribution"])[:5]
        ],
    }
    user_msg = (
        "Evidence for this risk:\n```json\n"
        + json.dumps(evidence, default=str, indent=2)
        + "\n```\n\nWrite the 2-3 sentence ranking explanation now."
    )
    out = _chat(
        messages=[{"role": "system", "content": EXPLAIN_SYSTEM}, {"role": "user", "content": user_msg}],
        temperature=0.2,
        max_tokens=200,
    )
    if out:
        return out
    return _template_explanation(rank, evidence)


def _template_explanation(rank: int, e: dict) -> str:
    """Deterministic fallback when the LLM is unreachable."""
    bits = []
    bits.append(f"Ranks #{rank} because it combines technical severity (CVSS {e['cvss']}) with business impact.")
    if e["internet_exposed"]:
        bits.append(f"The {e['asset']} is internet-exposed.")
    if e["ti_ransomware"] or e["kev_ransomware_use"]:
        actor = e.get("threat_actor") or "an active threat actor"
        camp = e.get("campaign") or "an active ransomware campaign"
        bits.append(f"It is targeted by {actor}'s '{camp}' campaign with ransomware association.")
    if e["business_service"]:
        bits.append(
            f"Compromise impacts {e['business_service']} (revenue impact: {e['business_revenue_impact']})."
        )
    if not e["edr_installed"]:
        bits.append("EDR is not installed, removing a key compensating control.")
    also = e.get("also_affects") or []
    if also:
        names = ", ".join(a.get("asset_name", "?") for a in also)
        bits.append(f"The same CVE also affects: {names}.")
    return " ".join(bits)


# ---------- Task 2: NIST control summary ----------

NIST_SUMMARY_SYSTEM = """You translate a NIST SP 800-53 control into a 2-3 sentence
plain-English summary that a technical manager could act on.

STRICT RULES:
- Use ONLY the provided NIST control text. Do not add controls, IDs, or
  recommendations that are not in the provided text.
- Do not embellish with statistics or examples not in the text.
- The first sentence should state what the control requires. The second sentence
  should state what it means concretely for the risk at hand.
- Maximum 60 words.
"""


def summarize_nist_control(control: dict, risk_context: dict) -> str:
    """Summarize the retrieved NIST control with the specific risk in mind."""
    if not control:
        return "No relevant NIST control was retrieved."

    user_msg = (
        f"NIST Control {control.get('control_id')} - {control.get('name')}\n"
        f"Control text:\n{control.get('text')}\n\n"
        f"Discussion:\n{control.get('discussion')}\n\n"
        f"Apply this to the following risk:\n"
        f"- Asset: {risk_context.get('asset_name')} ({risk_context.get('asset_type')})\n"
        f"- Vulnerability: {risk_context.get('vulnerability_name')} ({risk_context.get('cve')})\n"
        f"- Business service: {risk_context.get('business_service')}\n\n"
        f"Write the 2-3 sentence summary now."
    )
    out = _chat(
        messages=[{"role": "system", "content": NIST_SUMMARY_SYSTEM}, {"role": "user", "content": user_msg}],
        temperature=0.2,
        max_tokens=200,
    )
    if out:
        return out

    # Deterministic fallback: take a meaningful first sentence (NIST controls start with
    # "a. ..." enumerations, so naive split-on-period yields "a"; we strip those prefixes).
    text = (control.get("text") or "").strip()
    if not text:
        return f"NIST {control.get('control_id')} ({control.get('name')}) applies but text is unavailable."
    import re
    # Strip leading enumerator like "a. " or "1. " that appears at the start of NIST control text
    cleaned = re.sub(r"^[a-z0-9]+\.\s+", "", text)
    # Split into sentences by period followed by whitespace and a capital letter
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", cleaned)
    snippet = " ".join(sentences[:2]).strip()
    if len(snippet) > 280:
        snippet = snippet[:277].rsplit(" ", 1)[0] + "..."
    return f"NIST {control.get('control_id')} ({control.get('name')}): {snippet}"
