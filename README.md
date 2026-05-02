---
title: TawasolPay AI Cyber Risk Assistant
emoji: 🛡️
colorFrom: indigo
colorTo: red
sdk: streamlit
sdk_version: 1.39.0
app_file: app.py
pinned: false
license: mit
---

# TawasolPay — AI-Powered Cyber Risk Assistant

**Live demo:** https://huggingface.co/spaces/ps2285/tawasolpay-cyber-risk-assistant
**Source:** https://github.com/pratham-agarwalla/tawasolpay-cyber-risk-assistant

---

## What it does

Given TawasolPay's data pack (60 assets, 114 open vulnerabilities, 40 threat-intel records, 20 business services, plus an MDR threat advisory), the system:

1. **Joins the data** across the five CSVs by asset and CVE.
2. **Cross-references the live CISA KEV catalog** to confirm in-the-wild exploitation and known ransomware-campaign use.
3. **Scores each (asset, vulnerability) pair** with a deterministic, transparent formula whose weights follow the prioritization order TawasolPay's MDR analyst notes specify (internet exposure → active exploitation → ransomware → business criticality → missing controls). CVSS is one input among many — never the dominant one.
4. **Picks the top 5** distinct risks.
5. **Retrieves the most relevant NIST SP 800-53 Rev. 5 control** for each via embedding-based RAG over the official NIST control catalog (1,000+ controls).
6. **Asks an LLM (Groq, Llama 3.3 70B)** to do two narrow things only: (a) generate a 2–3 sentence plain-English explanation of why the risk ranks where it does, and (b) summarize the *retrieved* NIST control text. The LLM never scores, never invents controls.
7. **Renders five readable risk cards** in a Streamlit UI.

## Architecture

```
data/                         CSVs + threat report + bundled NIST fallback
src/
  data_loader.py              CSV ingestion + joins
  kev_enricher.py             Live CISA KEV download + enrich (+ disk cache)
  risk_scorer.py              Deterministic transparent scoring
  nist_rag.py                 NIST 800-53 download + chunk + embed + Chroma
  llm_client.py               Groq wrapper (with deterministic fallback)
  pipeline.py                 Orchestrator
app.py                        Streamlit UI
requirements.txt
```

The structured layer (assets, vulns, threat intel, business services) is queried with **Pandas joins** and a **deterministic scoring function**. The unstructured layer (NIST 800-53 Rev. 5 control catalog) is queried with **embeddings + ChromaDB**. The split is intentional and explained below.

## Run locally

```bash
git clone <this repo>
cd cyber-risk-assistant
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Set your Groq key (free at https://console.groq.com/keys)
cp .env.example .env
# edit .env and paste your GROQ_API_KEY

streamlit run app.py
```

First run takes ~60–90 seconds: it downloads the NIST 800-53 Rev. 5 catalog (~700 KB), the CISA KEV CSV (~400 KB), and downloads the `all-MiniLM-L6-v2` embedding model (~80 MB). All three are cached for subsequent runs.

If your environment cannot reach NIST or CISA, the system falls back to a bundled subset of authentic NIST control text (`data/nist_800_53_fallback.csv`) for the most relevant controls, and the page surfaces a banner saying so.

If `GROQ_API_KEY` is not set, the system runs in **deterministic fallback mode** — the explanations are template-generated and the NIST summaries return the first sentence of the retrieved control text. Rankings still work and the top 5 still surface; only the LLM-generated prose degrades.

## Deploy

The app is designed to run unchanged on Hugging Face Spaces (Streamlit SDK):

1. Create a new Space, SDK = Streamlit, Python 3.11.
2. Push this repo to the Space.
3. Add `GROQ_API_KEY` as a Space secret (Settings → Variables and secrets).
4. The Space will install `requirements.txt` and serve `app.py` on its public URL.

---

## Supporting question 1 — The data split

**What I embedded and why.** I embedded the NIST SP 800-53 Rev. 5 control catalog. Each control is one chunk (control ID + name + control text + discussion + related controls). I embedded with `sentence-transformers/all-MiniLM-L6-v2` and stored in ChromaDB. The reason: NIST controls are *prose*. There is no useful structure to filter on (you cannot say `WHERE control = 'thing about patching internet-exposed VPNs'`). Semantic similarity over the prose is exactly the right access pattern.

**What I queried as structured records and why.** Everything else: the asset inventory, the vulnerability list, the threat intel feed, the business services table, and the CISA KEV catalog. They have well-defined schemas, deterministic join keys (`asset_id`, `cve`, `business_service`), and the operations I need are filters and joins, not similarity. Embedding them would lose precision (an asset with `internet_exposed=Yes` is a *fact*, not a vector neighbor) and cost recall (you cannot reliably rank by *score* with cosine similarity). Pandas joins with a transparent additive scoring function keep the ranking explainable, reproducible, and auditable — three properties a CISO will want when defending a board recommendation.

## Supporting question 2 — Where it goes wrong

1. **Stale or missing CISA KEV match.** If a CVE in `vulnerabilities.csv` does not appear in the CISA KEV catalog (e.g., a brand-new CVE, a renamed CVE, or any of the synthetic `CVE-SYN-*` IDs in this dataset), the system will not flag it as actively exploited via KEV — even if the in-house threat intel feed says it is being exploited. **Mitigation:** the scoring already double-counts exploitation evidence: `exploit_available_b` from `vulnerabilities.csv`, KEV listing, and any matching threat-intel campaign each contribute independently. So a vuln missed by KEV but flagged by in-house TI still scores high. We surface KEV freshness and match counts in the sidebar so the analyst can see when the catalog is stale.

2. **Threat-intel "noise" mislabels a vulnerability.** The TI feed contains 15 records with no match in the environment, plus inevitable mislabels — e.g., `TI-3018` tags `CVE-SYN-2026-0010` (a Payment API IDOR) as "CitrixBleed Exploitation" by IronVeil, which is wrong. The LLM-written explanation could repeat this mislabel and mislead a reader. **Mitigation:** the system always shows the *evidence* alongside the explanation (asset name, CVE, vulnerability name, business service, full TI summary), so a reader can spot the mismatch. The LLM prompt is also pinned to "use ONLY the provided evidence; do not introduce CVEs or actors not in the input." A stronger fix (left for later) would be a sanity check that the campaign's `target_sector` is at least loosely consistent with the affected component before counting the TI match in the score.

3. **NIST RAG retrieves a near-but-wrong control.** Embedding-based retrieval can return a topically close control that is not the operationally most relevant one — for example, returning AC-2 (Account Management) for an OpenSSH RCE when SI-2 (Flaw Remediation) or SC-7 (Boundary Protection) would be better. **Mitigation:** the query is composed from multiple signals (vulnerability name + affected component + asset type + the one-line remediation hint from `remediation_guidance.csv`) so the embedded query carries strong patch/flaw-remediation language. We display the *full verbatim NIST control text* in an expander beside the LLM summary, so the reader can immediately see whether the retrieved control fits. The LLM is never allowed to invent a control ID — only to summarize what we retrieved.

## Supporting question 3 — One thing I would change

**Replace the single-control retrieval with a top-3 retrieve + LLM-pick-best-with-justification step.** Right now the system retrieves the single closest NIST control by cosine similarity, which works for clear cases (Fortinet RCE → SI-2 Flaw Remediation) but is brittle for compound risks (a missing-EDR-on-internet-exposed-Confluence-with-stale-credentials risk really wants SI-2 *and* SI-3 *and* AC-2). I would retrieve the top 3 controls, pass all three's prose to the LLM, and have it select the one most operationally applicable to the specific risk *and* explain why the others were rejected. That gives the reader a stronger signal of fit and an audit trail, at the cost of one extra LLM call per risk. It is the single change that would most improve the perceived quality of the remediation guidance without changing anything about the scoring engine.

---

## Models, libraries, sources

- **LLM:** Groq, `llama-3.3-70b-versatile` (free tier; configurable via `GROQ_MODEL`)
- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` (local, free)
- **Vector store:** ChromaDB (persistent, local disk)
- **Public sources:** [CISA KEV CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) and [NIST SP 800-53 Rev. 5 Control Catalog CSV](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads)
- **Framework:** Streamlit
