from __future__ import annotations
from pathlib import Path
import logging
import time
import json
import pandas as pd
import requests

log = logging.getLogger(__name__)
NIST_OSCAL_JSON = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
NIST_URL_CSV1 = (
    "https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/docs/"
    "sp800-53r5-control-catalog.csv"
)
NIST_URL_CSV2 = (
    "https://csrc.nist.gov/CSRC/media/Publications/sp/800-53/rev-5/final/"
    "documents/sp800-53r5-control-catalog.csv"
)

CACHE_FILE = Path("cache/nist_800_53_r5.csv")
CHROMA_DIR = Path("cache/chroma")
COLLECTION = "nist_800_53"
CACHE_TTL = 30 * 24 * 3600 


def _cache_fresh(p: Path) -> bool:
    return p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL


def _oscal_json_to_df(catalog_json: dict) -> pd.DataFrame:
    rows = []

    def _prose_for(control: dict, part_name: str) -> str:
        for p in control.get("parts", []) or []:
            if p.get("name") == part_name:
                bits = []
                if p.get("prose"):
                    bits.append(p["prose"])
                for sp in p.get("parts", []) or []:
                    label = ""
                    for prop in sp.get("props", []) or []:
                        if prop.get("name") == "label":
                            label = prop["value"] + " "
                            break
                    if sp.get("prose"):
                        bits.append(label + sp["prose"])
                    for ssp in sp.get("parts", []) or []:
                        sl = ""
                        for prop in ssp.get("props", []) or []:
                            if prop.get("name") == "label":
                                sl = prop["value"] + " "
                                break
                        if ssp.get("prose"):
                            bits.append("    " + sl + ssp["prose"])
                return "\n".join(bits)
        return ""

    def _related(control: dict) -> str:
        rel = []
        for link in control.get("links", []) or []:
            if link.get("rel") == "related":
                href = link.get("href", "")
                if href.startswith("#"):
                    rel.append(href[1:].upper())
        return ", ".join(rel)

    def _walk(control: dict):
        cid = control.get("id", "").upper()
        name = control.get("title", "")
        statement = _prose_for(control, "statement")
        guidance = _prose_for(control, "guidance")
        rows.append(
            {
                "Control Identifier": cid,
                "Control (or Control Enhancement) Name": name,
                "Control Text": statement,
                "Discussion": guidance,
                "Related Controls": _related(control),
            }
        )

        for sub in control.get("controls", []) or []:
            _walk(sub)

    catalog = catalog_json.get("catalog", catalog_json)
    for grp in catalog.get("groups", []) or []:
        for ctrl in grp.get("controls", []) or []:
            _walk(ctrl)
    return pd.DataFrame(rows)


def fetch_nist_catalog(force: bool = False, cache_file: Path = CACHE_FILE) -> tuple[pd.DataFrame | None, str]:
    cache_file.parent.mkdir(parents=True, exist_ok=True)

    if not force and _cache_fresh(cache_file):
        try:
            df = pd.read_csv(cache_file)
            return df, f"loaded from cache ({len(df)} rows)"
        except Exception as e:
            log.warning("NIST cache unreadable: %s", e)

    last_err = None

    try:
        r = requests.get(
            NIST_OSCAL_JSON, timeout=60,
            headers={"User-Agent": "cyber-risk-assistant/1.0"},
        )
        r.raise_for_status()
        catalog_json = r.json()
        df = _oscal_json_to_df(catalog_json)
        if not df.empty:
            df.to_csv(cache_file, index=False)
            return df, f"downloaded OSCAL JSON from NIST GitHub ({len(df)} controls)"
    except Exception as e:
        last_err = e
        log.warning("NIST OSCAL fetch failed: %s", e)

    for url in (NIST_URL_CSV1, NIST_URL_CSV2):
        try:
            r = requests.get(url, timeout=60, headers={"User-Agent": "cyber-risk-assistant/1.0"})
            r.raise_for_status()
            cache_file.write_bytes(r.content)
            df = pd.read_csv(cache_file)
            return df, f"downloaded fresh from NIST CSV ({len(df)} rows)"
        except Exception as e:
            last_err = e
            log.warning("NIST CSV fetch failed: %s", e)

    if cache_file.exists():
        try:
            df = pd.read_csv(cache_file)
            return df, f"network unavailable; using stale cache ({len(df)} rows)"
        except Exception as e:
            log.warning("Stale cache unreadable: %s", e)

    fallback = Path("data/nist_800_53_fallback.csv")
    if fallback.exists():
        try:
            df = pd.read_csv(fallback)
            return (
                df,
                f"network unavailable; using bundled NIST control subset ({len(df)} controls). "
                f"For full coverage, ensure the host has network access to GitHub or NIST.",
            )
        except Exception as e:
            return None, f"network unavailable and bundled fallback unreadable: {e}"
    return None, f"network unavailable, no cache, no fallback: {last_err}"


def _normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    rename_map = {}
    for c in df.columns:
        cl = c.lower()
        if "control identifier" in cl or cl == "control id" or cl == "id":
            rename_map[c] = "control_id"
        elif cl == "control name" or "(or control enhancement) name" in cl or "control (or control enhancement) name" in cl:
            rename_map[c] = "name"
        elif cl == "control text" or cl == "control":
            rename_map[c] = "text"
        elif cl == "discussion":
            rename_map[c] = "discussion"
        elif "related" in cl:
            rename_map[c] = "related"
    df = df.rename(columns=rename_map)
    for col in ("control_id", "name", "text", "discussion", "related"):
        if col not in df.columns:
            df[col] = ""
    df = df.fillna("")
    df["control_id"] = df["control_id"].astype(str).str.strip()
    df = df[df["control_id"] != ""]
    return df


def build_chunks(df: pd.DataFrame) -> list[dict]:
    df = _normalise_columns(df)
    chunks = []
    for _, r in df.iterrows():
        cid = str(r["control_id"]).strip()
        name = str(r["name"]).strip()
        text = str(r["text"]).strip()
        discussion = str(r["discussion"]).strip()
        related = str(r["related"]).strip()
        embed_text = f"{cid} {name}\n\n{text}\n\nDiscussion: {discussion}\n\nRelated: {related}".strip()
        chunks.append(
            {
                "id": cid,
                "embed_text": embed_text,
                "metadata": {
                    "control_id": cid,
                    "name": name,
                    "text": text[:4000],
                    "discussion": discussion[:4000],
                    "related": related[:1000],
                },
            }
        )
    return chunks


class _KeywordFallbackIndex:

    def __init__(self, chunks: list[dict]):
        self.chunks = chunks
        self._toks = [
            set(t for t in (c["embed_text"].lower().replace("/", " ").split()) if len(t) > 2)
            for c in chunks
        ]

    def count(self) -> int:
        return len(self.chunks)

    def query(self, query_texts, n_results=1):
        q = (query_texts[0] or "").lower()
        q_toks = set(t for t in q.replace("/", " ").split() if len(t) > 2)
        scored = []
        for i, toks in enumerate(self._toks):
            overlap = len(q_toks & toks)
            scored.append((overlap, i))
        scored.sort(reverse=True)
        top = scored[:n_results]
        ids = [[self.chunks[i]["id"] for _, i in top]]
        metas = [[self.chunks[i]["metadata"] for _, i in top]]
        dists = [[1.0 / (1 + s) for s, _ in top]]
        return {"ids": ids, "metadatas": metas, "distances": dists}


def get_or_build_index(force_rebuild: bool = False):
    def _build_keyword_fallback(reason: str):
        df, status = fetch_nist_catalog()
        if df is None:
            return None, f"FAILED: {status}"
        chunks = build_chunks(df)
        return (
            _KeywordFallbackIndex(chunks),
            f"keyword fallback ({reason}; {len(chunks)} chunks); {status}",
        )

    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except Exception as e:
        log.warning("ChromaDB unavailable (%s); using keyword fallback", e)
        return _build_keyword_fallback(f"chromadb missing: {e}")

    try:
        embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
    except Exception as e:
        log.warning("sentence-transformers unavailable (%s); using keyword fallback", e)
        return _build_keyword_fallback(f"sentence-transformers missing: {e}")

    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    if force_rebuild:
        try:
            client.delete_collection(COLLECTION)
        except Exception:
            pass

    existing = {c.name for c in client.list_collections()}
    if COLLECTION in existing and not force_rebuild:
        col = client.get_collection(COLLECTION, embedding_function=embed_fn)
        if col.count() > 0:
            return col, f"loaded existing index ({col.count()} chunks)"

    col = client.get_or_create_collection(COLLECTION, embedding_function=embed_fn)

    df, status = fetch_nist_catalog()
    if df is None:
        return col, f"FAILED: {status}"
    chunks = build_chunks(df)
    if not chunks:
        return col, "FAILED: no chunks parsed from NIST CSV"

    BATCH = 256
    for i in range(0, len(chunks), BATCH):
        batch = chunks[i : i + BATCH]
        col.add(
            ids=[c["id"] for c in batch],
            documents=[c["embed_text"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )
    return col, f"built index ({len(chunks)} chunks); {status}"


def build_query_for_risk(risk_row) -> str:
    """Compose a focused retrieval query from the risk row."""
    parts = [
        str(risk_row.get("vulnerability_name") or ""),
        str(risk_row.get("affected_component") or ""),
        str(risk_row.get("asset_type") or ""),
        str(risk_row.get("vendor_product") or ""),
    ]
    rem_hint = risk_row.get("remediation_hint") or ""
    if rem_hint:
        parts.append(str(rem_hint))
    parts.append("remediation patch flaw vulnerability monitoring")
    return " | ".join(p for p in parts if p)


def retrieve_control(col, risk_row, n_results: int = 1):
    query = build_query_for_risk(risk_row)
    res = col.query(query_texts=[query], n_results=n_results)
    if not res or not res.get("ids") or not res["ids"][0]:
        return None
    md = res["metadatas"][0][0]
    return {
        "control_id": md.get("control_id"),
        "name": md.get("name"),
        "text": md.get("text"),
        "discussion": md.get("discussion"),
        "related": md.get("related"),
        "distance": res.get("distances", [[None]])[0][0],
        "query": query,
    }
