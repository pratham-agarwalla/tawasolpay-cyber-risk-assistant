"""TawasolPay AI Cyber Risk Assistant - Streamlit UI."""
import os
import sys
import time
import logging
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")

st.set_page_config(
    page_title="TawasolPay - AI Cyber Risk Assistant",
    page_icon="shield",
    layout="wide",
)


@st.cache_resource(show_spinner="Building risk picture (KEV download + NIST embeddings on first run)...")
def get_pipeline_result():
    """Cached pipeline run. Reuses the prebuilt Chroma index and KEV cache on subsequent reruns."""
    from src.pipeline import run_pipeline
    return run_pipeline(data_dir="data", top_k=5)


def header():
    st.title("TawasolPay - AI Cyber Risk Assistant")
    st.caption(
        "Joins asset inventory, open vulnerabilities, threat intel, and business "
        "service context into a prioritized, explainable top-5 risk list. "
        "Remediation guidance is retrieved from NIST SP 800-53 Rev. 5 via RAG."
    )


def sidebar(result):
    with st.sidebar:
        st.subheader("Data ingest")
        s = result["stats"]
        st.metric("Assets", s["n_assets"])
        st.metric("Open vulnerabilities", s["n_vulns"])
        st.metric("Threat-intel records", s["n_ti"])
        st.metric("Business services", s["n_business_services"])
        st.divider()
        st.subheader("Cross-references")
        st.metric("Internet-exposed assets", s["n_internet_exposed_assets"])
        st.metric("Vulns matched to threat-intel", s["n_ti_matched_vulns"])
        st.metric("Vulns in CISA KEV", s["n_kev_listed"])
        st.metric("KEV: ransomware-tagged", s["n_kev_ransomware"])
        st.divider()
        st.caption("**KEV catalog:** " + result["kev_status"])
        st.caption("**NIST 800-53 index:** " + result["nist_status"])
        if not os.getenv("GROQ_API_KEY"):
            st.warning(
                "GROQ_API_KEY is not set. Explanations and NIST summaries are running "
                "in deterministic fallback mode."
            )
        if st.button("Force rebuild (fresh KEV + NIST)"):
            st.cache_resource.clear()
            for p in ["cache/kev.csv", "cache/nist_800_53_r5.csv"]:
                try:
                    Path(p).unlink()
                except FileNotFoundError:
                    pass
            try:
                import shutil
                shutil.rmtree("cache/chroma", ignore_errors=True)
            except Exception:
                pass
            st.rerun()


def risk_card(risk: dict):
    r = risk["row"]
    rank = risk["rank"]
    score = risk["score"]
    nist = risk["nist_control"] or {}

    asset = r.get("asset_name", "?")
    asset_type = r.get("asset_type", "")
    env = r.get("environment", "")
    bs = r.get("business_service", "?")
    vname = r.get("vulnerability_name", "?")
    cve = r.get("cve", "?")
    cvss = r.get("cvss", "?")
    actor = r.get("threat_actor")
    campaign = r.get("campaign_name")
    summary = r.get("summary")
    rev = r.get("revenue_impact", "")
    customer_facing = r.get("customer_facing", "")
    compliance = r.get("compliance_scope", "")
    days_open = r.get("days_open", "")
    edr = "Yes" if r.get("edr_installed_b") else "No"

    with st.container(border=True):
        cols = st.columns([0.7, 0.3])
        with cols[0]:
            st.markdown(f"### #{rank}  {asset}  &nbsp; `{cve}`")
            st.markdown(
                f"**{vname}**  "
                f"&nbsp;|&nbsp; CVSS **{cvss}**  "
                f"&nbsp;|&nbsp; {asset_type} ({env})"
            )
        with cols[1]:
            st.metric("Risk score", f"{score:.1f}")

        also = r.get("also_affects") or []
        if also:
            also_str = ", ".join(
                f"**{a['asset_name']}** ({a['business_service']})" for a in also
            )
            st.info(f"**Same CVE also present on:** {also_str}")

        st.markdown(f"> {risk['explanation']}")

        evidence_cols = st.columns(3)
        with evidence_cols[0]:
            st.markdown("**Asset & service**")
            st.write(
                f"- Asset: `{r.get('asset_id')}`  \n"
                f"- Owner: {r.get('owner_team') or '_unassigned_'}  \n"
                f"- Internet-exposed: {'Yes' if r.get('internet_exposed_b') or r.get('internet_exposed_vuln_b') else 'No'}  \n"
                f"- EDR installed: {edr}  \n"
                f"- Days open: {days_open}"
            )
        with evidence_cols[1]:
            st.markdown("**Business service at risk**")
            st.write(
                f"- Service: **{bs}**  \n"
                f"- Revenue impact: {rev}  \n"
                f"- Customer-facing: {customer_facing}  \n"
                f"- Compliance: {compliance}"
            )
        with evidence_cols[2]:
            st.markdown("**Matched threat intel**")
            if actor:
                st.write(
                    f"- Actor: **{actor}**  \n"
                    f"- Campaign: {campaign}  \n"
                    f"- Ransomware-associated: {r.get('ransomware_association', 'No')}  \n"
                    f"- Region/sector: {r.get('target_region', '?')} / {r.get('target_sector', '?')}"
                )
                if summary:
                    with st.expander("Threat-intel summary"):
                        st.write(summary)
            else:
                st.write("_No matching active campaign in TI feed._")

        st.markdown("---")
        st.markdown(
            f"**Recommended NIST 800-53 control: "
            f"`{nist.get('control_id', '?')}` - {nist.get('name', '?')}**"
        )
        st.write(risk["nist_summary"])
        with st.expander("Show full NIST control text (verbatim from NIST SP 800-53 Rev. 5)"):
            st.markdown(f"**Control:**\n\n{nist.get('text', '_unavailable_')}")
            if nist.get("discussion"):
                st.markdown(f"\n**Discussion:**\n\n{nist.get('discussion')}")
            if nist.get("related"):
                st.caption(f"Related controls: {nist.get('related')}")

        with st.expander("Why this score (factor breakdown)"):
            for f in sorted(risk["factors"], key=lambda x: -x["contribution"]):
                st.write(
                    f"- **{f['label']}** ({f['value']}): contribution +{f['contribution']:.1f}"
                )


def main():
    header()
    t0 = time.time()
    result = get_pipeline_result()
    t1 = time.time()

    sidebar(result)

    st.markdown(f"#### Top 5 prioritized risks  \n_Generated in {t1 - t0:.1f}s_")
    for risk in result["top_risks"]:
        risk_card(risk)

    with st.expander("MDR threat advisory (input context)"):
        st.markdown(result["threat_report"])

    st.divider()
    st.caption(
        "All threat actors, IOCs, and business data in this demo are synthetic. "
        "Source code: see GitHub link in the README."
    )


if __name__ == "__main__":
    main()
