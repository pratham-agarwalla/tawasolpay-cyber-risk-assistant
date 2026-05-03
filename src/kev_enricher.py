from __future__ import annotations
from pathlib import Path
import time
import logging
import pandas as pd
import requests

log = logging.getLogger(__name__)

KEV_URL_PRIMARY = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
KEV_URL_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv"

CACHE_FILE = Path("cache/kev.csv")
CACHE_TTL_SECONDS = 24 * 3600


def _cache_fresh(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < CACHE_TTL_SECONDS


def fetch_kev(force: bool = False, cache_file: Path = CACHE_FILE) -> tuple[pd.DataFrame | None, str]:
    cache_file.parent.mkdir(parents=True, exist_ok=True)

    if not force and _cache_fresh(cache_file):
        try:
            df = pd.read_csv(cache_file)
            return df, f"loaded from cache ({len(df)} entries)"
        except Exception as e:
            log.warning("KEV cache unreadable, refetching: %s", e)

    last_err = None
    for url in (KEV_URL_PRIMARY, KEV_URL_MIRROR):
        try:
            r = requests.get(url, timeout=30, headers={"User-Agent": "cyber-risk-assistant/1.0"})
            r.raise_for_status()
            cache_file.write_bytes(r.content)
            df = pd.read_csv(cache_file)
            return df, f"downloaded fresh from {url} ({len(df)} entries)"
        except Exception as e:
            last_err = e
            log.warning("KEV fetch failed from %s: %s", url, e)

    if cache_file.exists():
        try:
            df = pd.read_csv(cache_file)
            return df, f"network unavailable; using stale cache ({len(df)} entries): {last_err}"
        except Exception as e:
            return None, f"network unavailable and cache unreadable: {e}"
    return None, f"network unavailable and no cache: {last_err}"


def enrich_with_kev(vulns: pd.DataFrame, kev: pd.DataFrame | None) -> pd.DataFrame:
    out = vulns.copy()
    out["kev_listed"] = False
    out["kev_ransomware"] = False
    out["kev_date_added"] = None
    out["kev_required_action"] = None
    out["kev_short_description"] = None

    if kev is None or kev.empty:
        return out
    cve_col = "cveID" if "cveID" in kev.columns else next(
        (c for c in kev.columns if c.lower() == "cveid"), None
    )
    if cve_col is None:
        log.warning("KEV CSV missing cveID column; cols=%s", list(kev.columns))
        return out

    ransom_col = next(
        (c for c in kev.columns if c.lower() in ("knownransomwarecampaignuse", "knownransomware")),
        None,
    )
    date_col = next((c for c in kev.columns if c.lower() == "dateadded"), None)
    action_col = next((c for c in kev.columns if c.lower() == "requiredaction"), None)
    desc_col = next((c for c in kev.columns if c.lower() == "shortdescription"), None)

    kev_lookup = kev.set_index(cve_col)

    listed = []
    ransom = []
    dates = []
    actions = []
    descs = []
    for cve in out["cve"]:
        if isinstance(cve, str) and cve in kev_lookup.index:
            row = kev_lookup.loc[cve]
            if isinstance(row, pd.DataFrame):
                row = row.iloc[0]
            listed.append(True)
            ransom.append(
                str(row.get(ransom_col, "")).strip().lower() == "known"
                if ransom_col else False
            )
            dates.append(row.get(date_col) if date_col else None)
            actions.append(row.get(action_col) if action_col else None)
            descs.append(row.get(desc_col) if desc_col else None)
        else:
            listed.append(False)
            ransom.append(False)
            dates.append(None)
            actions.append(None)
            descs.append(None)

    out["kev_listed"] = listed
    out["kev_ransomware"] = ransom
    out["kev_date_added"] = dates
    out["kev_required_action"] = actions
    out["kev_short_description"] = descs
    return out
