from __future__ import annotations
import pandas as pd

W_CVSS = 1.0           
W_INTERNET = 12.0  
W_EXPLOIT = 8.0      
W_KEV = 6.0      
W_KEV_RANSOMWARE = 10.0 
W_TI_MATCH = 5.0      
W_TI_RANSOMWARE = 8.0 
W_TI_REGIONAL = 4.0  
W_BS_CRITICAL = 6.0    
W_BS_HIGH = 3.0     
W_CUSTOMER_FACING = 2.0
W_COMPLIANCE = 2.0  
W_ASSET_CRITICAL = 4.0
W_ASSET_HIGH = 2.0
W_NO_EDR = 4.0         
W_NO_PATCH = 3.0  
W_STALE = 2.0        
W_LONG_OPEN = 2.0      
W_PROD = 2.0          
W_NO_OWNER = 1.0  

REGIONAL_TERMS = {"middle east", "gulf", "uae", "global"}
RELEVANT_SECTORS = {
    "financial services", "fintech", "finance", "fintech and api-first",
    "all sectors", "enterprise",
}
COMPLIANCE_TRIGGERS = ("PCI", "GDPR", "SOC 2", "ISO 27001", "PDPL")


def _row_score(row: pd.Series) -> tuple[float, list[dict]]:
    factors: list[dict] = []

    def add(label: str, value: str, weight: float):
        factors.append(
            {"label": label, "value": value, "weight": weight, "contribution": weight}
        )

    score = 0.0

    cvss = float(row.get("cvss") or 0)
    score += cvss * W_CVSS
    factors.append(
        {
            "label": "CVSS base",
            "value": f"{cvss:.1f}",
            "weight": W_CVSS,
            "contribution": cvss * W_CVSS,
        }
    )
    is_internet = bool(row.get("internet_exposed_b")) or bool(row.get("internet_exposed_vuln_b"))
    if is_internet:
        score += W_INTERNET
        add("Internet exposed", "Yes", W_INTERNET)

    if bool(row.get("exploit_available_b")):
        score += W_EXPLOIT
        add("Exploit available", "Yes", W_EXPLOIT)

    if bool(row.get("kev_listed", False)):
        score += W_KEV
        add("In CISA KEV catalog", "Yes", W_KEV)
        if bool(row.get("kev_ransomware", False)):
            score += W_KEV_RANSOMWARE
            add("KEV: known ransomware use", "Yes", W_KEV_RANSOMWARE)

    if bool(row.get("has_ti_match")):
        score += W_TI_MATCH
        add(
            "Threat-intel campaign match",
            f"{row.get('threat_actor')} / {row.get('campaign_name')}",
            W_TI_MATCH,
        )
        if bool(row.get("ti_any_ransomware")):
            score += W_TI_RANSOMWARE
            add("TI campaign: ransomware-associated", "Yes", W_TI_RANSOMWARE)

        region = str(row.get("target_region") or "").lower()
        sector = str(row.get("target_sector") or "").lower()
        if any(t in region for t in REGIONAL_TERMS) or any(s in sector for s in RELEVANT_SECTORS):
            score += W_TI_REGIONAL
            add(
                "TI targets our region/sector",
                f"{row.get('target_region')} / {row.get('target_sector')}",
                W_TI_REGIONAL,
            )

    rev = str(row.get("revenue_impact") or "").strip()
    if rev == "Critical":
        score += W_BS_CRITICAL
        add("Business service revenue impact", "Critical", W_BS_CRITICAL)
    elif rev == "High":
        score += W_BS_HIGH
        add("Business service revenue impact", "High", W_BS_HIGH)

    if str(row.get("customer_facing") or "").lower() == "yes":
        score += W_CUSTOMER_FACING
        add("Customer-facing service", "Yes", W_CUSTOMER_FACING)

    compliance = str(row.get("compliance_scope") or "")
    if any(t in compliance for t in COMPLIANCE_TRIGGERS):
        score += W_COMPLIANCE
        add("Regulated compliance scope", compliance, W_COMPLIANCE)

    crit = str(row.get("criticality") or "")
    if crit == "Critical":
        score += W_ASSET_CRITICAL
        add("Asset criticality", "Critical", W_ASSET_CRITICAL)
    elif crit == "High":
        score += W_ASSET_HIGH
        add("Asset criticality", "High", W_ASSET_HIGH)

    if not bool(row.get("edr_installed_b", True)):
        score += W_NO_EDR
        add("EDR not installed", "Missing", W_NO_EDR)

    if not bool(row.get("patch_available_b", True)):
        score += W_NO_PATCH
        add("No vendor patch available", "Yes", W_NO_PATCH)

    if int(row.get("last_seen_days") or 0) > 30:
        score += W_STALE
        add("Asset stale (last seen > 30d)", str(row.get("last_seen_days")), W_STALE)
    if int(row.get("days_open") or 0) > 90:
        score += W_LONG_OPEN
        add("Vuln open > 90 days", str(row.get("days_open")), W_LONG_OPEN)
    if str(row.get("environment") or "") == "Production":
        score += W_PROD
        add("Production environment", "Yes", W_PROD)
    if pd.isna(row.get("owner_team")) or str(row.get("owner_team")).strip() == "":
        score += W_NO_OWNER
        add("No owning team assigned", "Yes", W_NO_OWNER)

    return score, factors


def score_risks(enriched: pd.DataFrame) -> pd.DataFrame:
    scores = []
    factors_list = []
    for _, row in enriched.iterrows():
        s, f = _row_score(row)
        scores.append(s)
        factors_list.append(f)
    out = enriched.copy()
    out["risk_score"] = scores
    out["risk_factors"] = factors_list
    return out.sort_values("risk_score", ascending=False).reset_index(drop=True)


def top_n(scored: pd.DataFrame, n: int = 5) -> pd.DataFrame:
    seen_cves = set()
    rows = []
    grouped = list(scored.groupby("cve", sort=False))
    by_cve = {cve: g for cve, g in grouped}
    for _, r in scored.iterrows():
        cve = r["cve"]
        if cve in seen_cves:
            continue
        seen_cves.add(cve)
        siblings = by_cve.get(cve)
        also = []
        if siblings is not None and len(siblings) > 1:
            for _, s in siblings.iterrows():
                if s["asset_id"] == r["asset_id"]:
                    continue
                also.append(
                    {
                        "asset_id": s["asset_id"],
                        "asset_name": s["asset_name"],
                        "business_service": s["business_service"],
                        "compliance_scope": s.get("compliance_scope"),
                    }
                )
        r = r.copy()
        r["also_affects"] = also
        rows.append(r)
        if len(rows) >= n:
            break
    return pd.DataFrame(rows).reset_index(drop=True)
