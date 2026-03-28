import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
from typing import Dict, List, Optional, Tuple
import json
import groq

# ---------- Page Configuration ----------
st.set_page_config(
    page_title="Vuln Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Load Secrets ----------
try:
    NVD_API_KEY = st.secrets["NVD_API_KEY"]
except:
    NVD_API_KEY = None

try:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except:
    GROQ_API_KEY = None
    st.warning("Groq API key not found. LLM features will be disabled.")

# ---------- Cached API Functions ----------
@st.cache_data(ttl=3600, show_spinner=False)
def fetch_nvd_cve(cve_id: str) -> Optional[Dict]:
    """
    Fetch a single CVE from NVD.
    Returns dict with cvss_score, exploitability_score, description.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data["vulnerabilities"]:
                vuln = data["vulnerabilities"][0]["cve"]
                metrics = vuln.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                score = cvss_v3.get("baseScore", "N/A")
                exploitability = cvss_v3.get("exploitabilityScore", "N/A")
                desc = vuln.get("descriptions", [{}])[0].get("value", "")
                return {
                    "cve": cve_id,
                    "cvss_score": score,
                    "exploitability_score": exploitability,
                    "description": desc,
                }
        else:
            st.error(f"NVD API error {resp.status_code} for {cve_id}")
    except Exception as e:
        st.error(f"Error fetching {cve_id}: {e}")
    return None

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_epss(cve_id: str) -> Optional[float]:
    """Fetch EPSS probability (0-1)."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data"):
                return float(data["data"][0]["epss"])
    except Exception:
        pass
    return None

@st.cache_data(ttl=86400, show_spinner=False)
def fetch_kev_catalog() -> List[Dict]:
    """Fetch the CISA KEV catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("vulnerabilities", [])
    except Exception:
        pass
    return []

def is_in_kev(cve_id: str, kev_list: List[Dict]) -> bool:
    """Check if CVE is present in KEV list."""
    for item in kev_list:
        if item.get("cveID") == cve_id:
            return True
    return False

def get_past_likelihood(exploitability_score, in_kev: bool) -> str:
    """Compute LEV from CVSS exploitability subscore and KEV status."""
    if in_kev:
        return "Confirmed (KEV)"
    if exploitability_score != "N/A":
        try:
            score = float(exploitability_score)
            if score >= 2.5:
                return "High"
            elif score >= 1.5:
                return "Medium"
            else:
                return "Low"
        except:
            pass
    return "Unknown"

@st.cache_data(ttl=3600, show_spinner=False)
def search_nvd(keyword: str, start_date: datetime, end_date: datetime, max_results: int = 50) -> List[Dict]:
    """
    Search NVD with keyword and date range. Returns list of CVE summaries.
    Implements basic pagination.
    """
    results = []
    start_index = 0
    while len(results) < max_results:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "startIndex": start_index,
            "resultsPerPage": min(50, max_results - len(results)),
        }
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break
                for item in vulns:
                    cve = item["cve"]
                    results.append({
                        "cve": cve["id"],
                        "description": cve["descriptions"][0]["value"],
                        "published": cve["published"],
                    })
                # Check if there are more results
                total = data.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total:
                    break
                # Respect rate limits
                time.sleep(0.2)
            else:
                st.error(f"NVD search error {resp.status_code}")
                break
        except Exception as e:
            st.error(f"Search error: {e}")
            break
    return results[:max_results]

def enrich_cve_data(cve_list: List[Dict]) -> pd.DataFrame:
    """
    Given a list of CVE dicts (with at least 'cve'), fetch full details,
    EPSS, and KEV status. Returns a DataFrame.
    """
    kev_list = fetch_kev_catalog()
    enriched = []
    for cve_info in cve_list:
        cve_id = cve_info["cve"]
        with st.spinner(f"Fetching {cve_id}..."):
            nvd = fetch_nvd_cve(cve_id)
            if nvd:
                epss = fetch_epss(cve_id)
                in_kev = is_in_kev(cve_id, kev_list)
                past_likelihood = get_past_likelihood(nvd["exploitability_score"], in_kev)
                enriched.append({
                    "CVE": cve_id,
                    "CVSS Score": nvd["cvss_score"],
                    "EPSS Probability": epss if epss is not None else "N/A",
                    "KEV": "Yes" if in_kev else "No",
                    "Past Likelihood (LEV)": past_likelihood,
                    "Description": nvd["description"][:200] + "..." if len(nvd["description"]) > 200 else nvd["description"],
                })
            else:
                enriched.append({
                    "CVE": cve_id,
                    "CVSS Score": "N/A",
                    "EPSS Probability": "N/A",
                    "KEV": "No",
                    "Past Likelihood (LEV)": "Unknown",
                    "Description": "Not found in NVD",
                })
    return pd.DataFrame(enriched)

# ---------- LLM Functions ----------
def llm_summarize(prompt: str) -> str:
    """Call Groq LLM to generate summary."""
    if not GROQ_API_KEY:
        return "LLM features disabled (missing API key)."
    client = groq.Groq(api_key=GROQ_API_KEY)
    try:
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="mixtral-8x7b-32768",
            temperature=0.3,
            max_tokens=1024,
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"LLM error: {e}"

# ---------- Streamlit UI ----------
def main():
    st.title("🛡️ Vulnerability Intelligence Dashboard")
    st.markdown("Aggregate **CVSS**, **EPSS**, **CISA KEV**, and compute **Past Likelihood (LEV)**. Powered by open‑source LLM (Groq).")

    # Sidebar for mode selection
    mode = st.sidebar.radio("Select Mode", ["Single CVE Lookup", "Search & Dashboard"])

    if mode == "Single CVE Lookup":
        st.header("🔍 Single CVE Lookup")
        cve_input = st.text_input("Enter a CVE ID (e.g., CVE-2023-12345)").strip()
        if st.button("Analyze CVE", type="primary"):
            if not cve_input:
                st.warning("Please enter a CVE ID.")
            else:
                with st.spinner("Fetching data..."):
                    nvd = fetch_nvd_cve(cve_input)
                    if not nvd:
                        st.error("CVE not found in NVD.")
                    else:
                        epss = fetch_epss(cve_input)
                        kev_list = fetch_kev_catalog()
                        in_kev = is_in_kev(cve_input, kev_list)
                        past_likelihood = get_past_likelihood(nvd["exploitability_score"], in_kev)

                        # Display in columns
                        col1, col2 = st.columns(2)
                        with col1:
                            st.subheader("📊 Vulnerability Data")
                            st.metric("CVSS Score", nvd["cvss_score"])
                            st.metric("EPSS Probability", f"{epss:.4f}" if epss else "N/A")
                            st.metric("In CISA KEV", "Yes" if in_kev else "No")
                            st.metric("Past Likelihood (LEV)", past_likelihood)
                        with col2:
                            st.subheader("📝 Description")
                            st.write(nvd["description"])

                        # LLM Summary
                        if st.button("Generate AI Summary"):
                            with st.spinner("Generating summary with Groq..."):
                                prompt = f"""
                                You are a cybersecurity analyst. Given the following vulnerability data, provide a concise risk assessment and recommended action.

                                CVE: {cve_input}
                                CVSS Score: {nvd['cvss_score']}
                                EPSS Probability: {epss if epss else 'N/A'}
                                In CISA KEV: {'Yes' if in_kev else 'No'}
                                Past Likelihood (LEV): {past_likelihood}
                                Description: {nvd['description']}

                                Please summarize the risk and suggest whether this should be patched urgently.
                                """
                                summary = llm_summarize(prompt)
                                st.markdown("### 🤖 AI Risk Summary")
                                st.write(summary)

    else:
        st.header("🔎 Search & Dashboard")
        # Search parameters
        col1, col2, col3 = st.columns(3)
        with col1:
            keyword = st.text_input("Search Keyword (e.g., 'Apache', 'RCE')")
        with col2:
            start_date = st.date_input("Published From", datetime.now() - timedelta(days=30))
        with col3:
            end_date = st.date_input("Published To", datetime.now())
        max_results = st.slider("Max CVEs to fetch", min_value=5, max_value=100, value=30, step=5)

        if st.button("Search & Build Dashboard", type="primary"):
            if not keyword:
                st.warning("Please enter a search keyword.")
            else:
                with st.spinner(f"Searching NVD for '{keyword}'..."):
                    cve_list = search_nvd(keyword, start_date, end_date, max_results)
                    if not cve_list:
                        st.info("No vulnerabilities found for the given criteria.")
                    else:
                        st.success(f"Found {len(cve_list)} CVEs. Enriching data...")
                        df = enrich_cve_data(cve_list)

                        # Display interactive table
                        st.subheader("📋 Vulnerability List")
                        st.dataframe(df, use_container_width=True)

                        # Visualizations
                        st.subheader("📈 Visualizations")
                        # Convert CVSS and EPSS to numeric for plotting
                        df_plot = df.copy()
                        df_plot["CVSS Score"] = pd.to_numeric(df_plot["CVSS Score"], errors="coerce")
                        df_plot["EPSS Probability"] = pd.to_numeric(df_plot["EPSS Probability"], errors="coerce")
                        df_plot = df_plot.dropna(subset=["CVSS Score"])

                        if not df_plot.empty:
                            # Bar chart of CVSS scores
                            fig1 = px.bar(
                                df_plot, x="CVE", y="CVSS Score",
                                color="Past Likelihood (LEV)",
                                title="CVSS Scores by Vulnerability",
                                labels={"CVSS Score": "CVSS v3 Score"},
                                height=500,
                            )
                            st.plotly_chart(fig1, use_container_width=True)

                            # Scatter plot: CVSS vs EPSS
                            df_scatter = df_plot.dropna(subset=["EPSS Probability"])
                            if not df_scatter.empty:
                                fig2 = px.scatter(
                                    df_scatter, x="CVSS Score", y="EPSS Probability",
                                    hover_name="CVE", color="Past Likelihood (LEV)",
                                    title="Risk Matrix: CVSS vs EPSS",
                                    labels={"CVSS Score": "CVSS v3 Score", "EPSS Probability": "EPSS (Exploit Probability)"},
                                )
                                st.plotly_chart(fig2, use_container_width=True)

                            # Summary statistics
                            st.subheader("📊 Summary Statistics")
                            col1, col2, col3 = st.columns(3)
                            col1.metric("Avg CVSS Score", f"{df_plot['CVSS Score'].mean():.2f}")
                            col2.metric("Max CVSS Score", f"{df_plot['CVSS Score'].max():.2f}")
                            col3.metric("KEV Count", len(df[df["KEV"] == "Yes"]))

                        # LLM Dashboard Summary
                        if st.button("Generate AI Dashboard Summary"):
                            with st.spinner("Generating executive summary..."):
                                # Prepare a concise prompt with the table summary
                                summary_stats = {
                                    "total_cves": len(df),
                                    "avg_cvss": df_plot["CVSS Score"].mean() if not df_plot.empty else 0,
                                    "max_cvss": df_plot["CVSS Score"].max() if not df_plot.empty else 0,
                                    "kev_count": len(df[df["KEV"] == "Yes"]),
                                    "high_lev_count": len(df[df["Past Likelihood (LEV)"] == "High"]),
                                }
                                prompt = f"""
                                You are a security analyst. Summarize the following vulnerability data for a security team.

                                Search Keyword: {keyword}
                                Date Range: {start_date} to {end_date}

                                Summary:
                                - Total CVEs found: {summary_stats['total_cves']}
                                - Average CVSS Score: {summary_stats['avg_cvss']:.2f}
                                - Maximum CVSS Score: {summary_stats['max_cvss']:.2f}
                                - Number of CVEs in CISA KEV: {summary_stats['kev_count']}
                                - Number of CVEs with High Past Likelihood: {summary_stats['high_lev_count']}

                                Provide a short executive summary highlighting the most critical risks and recommended next steps.
                                """
                                summary = llm_summarize(prompt)
                                st.markdown("### 🤖 Executive Summary")
                                st.write(summary)
                    st.success("Dashboard ready!")

if __name__ == "__main__":
    main()