"""End-to-end pipeline: data -> KEV enrichment -> scoring -> top-5 -> RAG -> LLM -> rendered output."""
from __future__ import annotations
import logging
import pandas as pd

from .data_loader import load_data_pack, build_enriched_view
from .kev_enricher import fetch_kev, enrich_with_kev
from .risk_scorer import score_risks, top_n
from .nist_rag import get_or_build_index, retrieve_control
from .llm_client import explain_ranking, summarize_nist_control

log = logging.getLogger(__name__)


def attach_remediation_hints(enriched: pd.DataFrame, remediation: pd.DataFrame) -> pd.DataFrame:
    """Best-effort fuzzy match of remediation_guidance.csv to vulnerabilities by finding_type
    against vulnerability_name. The hint is used only as a query-augmentation signal for RAG;
    the authoritative guidance comes from NIST.
    """
    out = enriched.copy()
    out["remediation_hint"] = ""
    if remediation is None or remediation.empty:
        return out
    rem = remediation.copy()
    rem["finding_type_lc"] = rem["finding_type"].astype(str).str.lower()

    def best_match(name: str) -> str:
        n = (name or "").lower()
        if not n:
            return ""
        # 1) substring match
        hits = rem[rem["finding_type_lc"].apply(lambda f: f in n or n in f)]
        if not hits.empty:
            return str(hits.iloc[0]["recommended_action"])
        # 2) keyword overlap
        toks = set(t for t in n.replace("(", " ").replace(")", " ").split() if len(t) > 3)
        rem["_overlap"] = rem["finding_type_lc"].apply(
            lambda f: len(set(f.split()) & toks)
        )
        if rem["_overlap"].max() >= 2:
            return str(rem.sort_values("_overlap", ascending=False).iloc[0]["recommended_action"])
        return ""

    out["remediation_hint"] = out["vulnerability_name"].apply(best_match)
    return out


def run_pipeline(data_dir: str = "data", top_k: int = 5) -> dict:
    """Returns:
    {
      'top_risks': [ {rank, score, row(dict), explanation, nist_control, nist_summary, factors}, ... ],
      'stats': {...},
      'kev_status': str,
      'nist_status': str,
    }
    """
    pack = load_data_pack(data_dir)

    kev_df, kev_status = fetch_kev()
    log.info("KEV: %s", kev_status)
    vulns_with_kev = enrich_with_kev(pack["vulnerabilities"], kev_df)
    pack["vulnerabilities"] = vulns_with_kev

    enriched = build_enriched_view(pack)
    enriched = attach_remediation_hints(enriched, pack["remediation_guidance"])

    scored = score_risks(enriched)
    top = top_n(scored, top_k)

    col, nist_status = get_or_build_index()
    log.info("NIST: %s", nist_status)

    top_risks = []
    for i, r in top.iterrows():
        rank = i + 1
        row_dict = r.to_dict()
        factors = row_dict.pop("risk_factors", [])
        nist = retrieve_control(col, r) if col else None
        nist_summary = summarize_nist_control(nist, row_dict) if nist else "NIST index unavailable."
        explanation = explain_ranking(rank, row_dict["risk_score"], row_dict, factors)
        top_risks.append(
            {
                "rank": rank,
                "score": row_dict["risk_score"],
                "row": row_dict,
                "factors": factors,
                "nist_control": nist,
                "nist_summary": nist_summary,
                "explanation": explanation,
            }
        )

    stats = {
        "n_assets": len(pack["assets"]),
        "n_vulns": len(pack["vulnerabilities"]),
        "n_ti": len(pack["threat_intelligence"]),
        "n_business_services": len(pack["business_services"]),
        "n_internet_exposed_assets": int(pack["assets"]["internet_exposed_b"].sum()),
        "n_kev_listed": int(vulns_with_kev["kev_listed"].sum()),
        "n_kev_ransomware": int(vulns_with_kev["kev_ransomware"].sum()),
        "n_ti_matched_vulns": int(enriched["has_ti_match"].sum()),
    }

    return {
        "top_risks": top_risks,
        "stats": stats,
        "kev_status": kev_status,
        "nist_status": nist_status,
        "threat_report": pack["threat_report"],
    }
