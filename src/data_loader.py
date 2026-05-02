"""Load and join the TawasolPay data pack."""
from __future__ import annotations
from pathlib import Path
import pandas as pd


def _yn(s: pd.Series) -> pd.Series:
    """Normalize Yes/No columns to bools."""
    return s.astype(str).str.strip().str.lower().eq("yes")


def load_data_pack(data_dir: str | Path = "data") -> dict[str, pd.DataFrame]:
    """Load all CSVs and the threat report. Returns a dict of dataframes + threat_report str."""
    data_dir = Path(data_dir)

    assets = pd.read_csv(data_dir / "assets.csv")
    vulns = pd.read_csv(data_dir / "vulnerabilities.csv")
    ti = pd.read_csv(data_dir / "threat_intelligence.csv")
    bs = pd.read_csv(data_dir / "business_services.csv")
    rg = pd.read_csv(data_dir / "remediation_guidance.csv")

    # Normalize boolean-ish columns
    assets["internet_exposed_b"] = _yn(assets["internet_exposed"])
    assets["edr_installed_b"] = _yn(assets["edr_installed"])
    vulns["exploit_available_b"] = _yn(vulns["exploit_available"])
    vulns["patch_available_b"] = _yn(vulns["patch_available"])
    vulns["internet_exposed_vuln_b"] = vulns["asset_exposure"].astype(str).str.strip().str.lower().eq("internet")
    ti["ransomware_b"] = _yn(ti["ransomware_association"])

    # Read threat report as a single string
    threat_report = (data_dir / "synthetic_threat_report.md").read_text(encoding="utf-8")

    return {
        "assets": assets,
        "vulnerabilities": vulns,
        "threat_intelligence": ti,
        "business_services": bs,
        "remediation_guidance": rg,
        "threat_report": threat_report,
    }


def build_enriched_view(d: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Join vulns -> assets -> business_services and attach matched threat-intel.

    Returns one row per (vuln, matching_ti). Vulns with no TI match get a single
    row with NaN TI columns (left join).
    """
    v = d["vulnerabilities"].copy()
    a = d["assets"].copy()
    b = d["business_services"].copy()
    ti = d["threat_intelligence"].copy()

    # Join asset facts onto vuln
    v_a = v.merge(
        a[
            [
                "asset_id", "asset_name", "asset_type", "environment", "owner_team",
                "business_service", "internet_exposed_b", "criticality",
                "data_classification", "edr_installed_b", "last_seen_days",
                "location", "vendor_product",
            ]
        ],
        on="asset_id",
        how="left",
    )

    # Join business service context
    v_a_b = v_a.merge(
        b.rename(columns={"business_impact": "bs_impact"}),
        on="business_service",
        how="left",
    )

    # Aggregate matching TI per CVE: keep the MOST severe TI match
    # severity proxy: ransomware first, then weaponized > active exploitation > others
    maturity_rank = {
        "Weaponized": 4,
        "Active Exploitation": 3,
        "Commodity Exploit": 2,
        "Proof of Concept": 1,
        "Social Engineering": 1,
        "Not Applicable": 0,
    }
    ti = ti.assign(_mat=ti["exploit_maturity"].map(maturity_rank).fillna(0))
    ti_sorted = ti.sort_values(["ransomware_b", "_mat"], ascending=[False, False])

    # For each CVE, keep the top TI record
    ti_top = (
        ti_sorted.dropna(subset=["matched_cve_or_control"])
        .drop_duplicates(subset=["matched_cve_or_control"], keep="first")
    )

    # Also compute aggregates per CVE (any ransomware match? count of campaigns?)
    ti_agg = (
        ti.groupby("matched_cve_or_control", as_index=False)
        .agg(
            ti_campaign_count=("campaign_name", "nunique"),
            ti_any_ransomware=("ransomware_b", "max"),
        )
    )

    enriched = v_a_b.merge(
        ti_top[
            [
                "matched_cve_or_control", "threat_actor", "campaign_name",
                "target_sector", "target_region", "exploit_maturity",
                "active_last_seen", "ransomware_association", "confidence",
                "summary",
            ]
        ].rename(columns={"matched_cve_or_control": "cve"}),
        on="cve",
        how="left",
    )

    enriched = enriched.merge(
        ti_agg.rename(columns={"matched_cve_or_control": "cve"}),
        on="cve",
        how="left",
    )

    enriched["ti_campaign_count"] = enriched["ti_campaign_count"].fillna(0).astype(int)
    enriched["ti_any_ransomware"] = enriched["ti_any_ransomware"].fillna(False).infer_objects(copy=False).astype(bool)
    enriched["has_ti_match"] = enriched["threat_actor"].notna()

    return enriched
