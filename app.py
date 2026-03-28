import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
import json
from typing import Dict, List, Optional, Tuple

# ---------- Page Configuration ----------
st.set_page_config(
    page_title="OT Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Load Secrets ----------
try:
    NVD_API_KEY = st.secrets.get("NVD_API_KEY", None)
except:
    NVD_API_KEY = None

try:
    HF_API_KEY = st.secrets["HF_API_KEY"]
except:
    HF_API_KEY = None

# ---------- Helper Functions ----------
def safe_float(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return 0.0

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_nvd_cve(cve_id: str) -> Optional[Dict]:
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
                desc = vuln.get("descriptions", [{}])[0].get("value", "")
                return {"cve": cve_id, "cvss_score": score, "description": desc}
    except Exception:
        pass
    return None

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_epss(cve_id: str) -> Optional[float]:
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
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("vulnerabilities", [])
    except Exception:
        pass
    return []

def is_in_kev(cve_id: str, kev_list: List[Dict]) -> bool:
    for item in kev_list:
        if item.get("cveID") == cve_id:
            return True
    return False

def fetch_ics_advisories() -> List[Dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/ics-advisories.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("advisories", [])
    except Exception:
        pass
    return []

def search_nvd(keyword: str, max_results: int = 20, lookback_months: int = 24) -> Tuple[List[Dict], int]:
    """Search NVD for CVEs matching keyword. Returns (list, total_count)."""
    start_date = datetime.now() - timedelta(days=lookback_months * 30)
    end_date = datetime.now()
    results = []
    start_index = 0
    total_count = 0
    while len(results) < max_results:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000Z"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999Z"),
            "startIndex": start_index,
            "resultsPerPage": min(50, max_results - len(results)),
        }
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                total_count = data.get("totalResults", 0)
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
                start_index += len(vulns)
                if start_index >= total_count:
                    break
                time.sleep(0.2)
            elif resp.status_code == 404:
                break
            else:
                st.error(f"NVD search error {resp.status_code}")
                break
        except Exception as e:
            st.error(f"Search error: {e}")
            break
    return results[:max_results], total_count

def enrich_cve(cve_id: str, kev_list: List[Dict]) -> Dict:
    nvd = fetch_nvd_cve(cve_id)
    if not nvd:
        return None
    epss = fetch_epss(cve_id)
    in_kev = is_in_kev(cve_id, kev_list)
    try:
        cvss = float(nvd["cvss_score"])
    except (ValueError, TypeError):
        cvss = "N/A"
    return {
        "cve": cve_id,
        "cvss_score": cvss,
        "epss": epss,
        "kev": in_kev,
        "description": nvd["description"]
    }

def analyze_assets(df, column_map, lookback_months=24):
    """Analyze each asset using mapped columns (asset_name, asset_type, vendor, model)."""
    kev_list = fetch_kev_catalog()
    all_vulns = []
    debug_info = []  # (asset_name, query, results_count)
    for _, row in df.iterrows():
        terms = []
        for field in ["asset_name", "asset_type", "vendor", "model"]:
            col = column_map.get(field)
            if col and pd.notna(row[col]) and str(row[col]).strip():
                terms.append(str(row[col]).strip())
        if not terms:
            continue
        query = " ".join(terms)
        cve_list, total_count = search_nvd(query, max_results=10, lookback_months=lookback_months)
        debug_info.append((row.get(column_map.get("asset_name", ""), "Unknown"), query, total_count))
        for cve_info in cve_list:
            enriched = enrich_cve(cve_info["cve"], kev_list)
            if enriched:
                enriched["asset"] = row.get(column_map.get("asset_name", ""), "Unknown")
                enriched["asset_type"] = row.get(column_map.get("asset_type", ""), "")
                enriched["vendor"] = row.get(column_map.get("vendor", ""), "")
                enriched["model"] = row.get(column_map.get("model", ""), "")
                all_vulns.append(enriched)
    df_vulns = pd.DataFrame(all_vulns)
    return df_vulns, debug_info

def manual_asset_search(asset_names, lookback_months=24):
    """Process a list of asset names (strings) and return vulnerabilities DataFrame."""
    kev_list = fetch_kev_catalog()
    all_vulns = []
    debug_info = []
    for asset_name in asset_names:
        query = asset_name.strip()
        if not query:
            continue
        cve_list, total_count = search_nvd(query, max_results=10, lookback_months=lookback_months)
        debug_info.append((asset_name, query, total_count))
        for cve_info in cve_list:
            enriched = enrich_cve(cve_info["cve"], kev_list)
            if enriched:
                enriched["asset"] = asset_name
                all_vulns.append(enriched)
    df_vulns = pd.DataFrame(all_vulns)
    return df_vulns, debug_info

def generate_threat_summary(df_vulns, assets_count):
    """Generate AI summary using Hugging Face Inference API."""
    if df_vulns.empty:
        return "No vulnerabilities found for the uploaded assets."
    top_cves = df_vulns.nlargest(10, "cvss_score")[["cve", "cvss_score", "kev", "description"]]
    summary_stats = {
        "total_vulns": len(df_vulns),
        "critical": len(df_vulns[df_vulns["cvss_score"] >= 9.0]),
        "high": len(df_vulns[(df_vulns["cvss_score"] >= 7.0) & (df_vulns["cvss_score"] < 9.0)]),
        "kev_count": df_vulns["kev"].sum(),
        "assets_affected": df_vulns["asset"].nunique(),
        "top_assets": df_vulns.groupby("asset").size().sort_values(ascending=False).head(5).to_dict(),
    }
    prompt = f"""You are a cybersecurity analyst. Based on the following vulnerability data from NVD, EPSS, and CISA KEV, provide a concise summary of the threat landscape for the uploaded OT assets.

Assets analyzed: {assets_count}

Vulnerability statistics:
- Total vulnerabilities found: {summary_stats['total_vulns']}
- Critical (CVSS >= 9.0): {summary_stats['critical']}
- High (CVSS 7.0-8.9): {summary_stats['high']}
- Known exploited (CISA KEV): {summary_stats['kev_count']}
- Assets affected: {summary_stats['assets_affected']}
- Top affected assets: {json.dumps(summary_stats['top_assets'])}

Top 10 CVEs by CVSS score:
{top_cves.to_string()}

Also consider any relevant ICS‑CERT advisories that might affect these assets (not included here). 
Write a brief summary highlighting the most critical risks and recommended immediate actions."""
    
    if not HF_API_KEY:
        return "Hugging Face API key not configured. Cannot generate summary."

    url = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {
        "inputs": f"<s>[INST] {prompt} [/INST]",
        "parameters": {
            "max_new_tokens": 800,
            "temperature": 0.3,
            "return_full_text": False
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list) and len(data) > 0:
            return data[0].get("generated_text", "No response").strip()
        else:
            return "Error: Unexpected response format."
    except Exception as e:
        return f"Error generating summary: {e}"

def hf_chat(prompt: str, context: str) -> str:
    """Chat using Hugging Face Inference API."""
    if not HF_API_KEY:
        return "Hugging Face API key not configured."
    url = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    system_msg = f"You are a cybersecurity analyst specialized in OT/ICS vulnerabilities. Use the following asset context to answer questions.\n\nAsset Context:\n{context}\n\n"
    full_prompt = f"<s>[INST] {system_msg}{prompt} [/INST]"
    payload = {
        "inputs": full_prompt,
        "parameters": {
            "max_new_tokens": 512,
            "temperature": 0.3,
            "return_full_text": False
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list) and len(data) > 0:
            return data[0].get("generated_text", "No response").strip()
        else:
            return "Error: Unexpected response format."
    except Exception as e:
        return f"Error: {e}"

# ---------- Streamlit UI ----------
def main():
    st.title("🛡️ OT Threat Intelligence")
    st.markdown("Upload an Excel/CSV file with your OT assets, then map columns to asset fields. The AI will analyze vulnerabilities and provide a summary.")

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        lookback_months = st.slider(
            "Lookback months (how far back to search for CVEs)",
            min_value=1, max_value=120, value=24, step=1,
            help="Increase if you want to see older CVEs."
        )
        st.session_state.lookback_months = lookback_months

        st.markdown("---")
        st.subheader("🔎 Quick Keyword Test")
        test_keyword = st.text_input("Enter a keyword (e.g., 'Siemens S7-1200')")
        if st.button("Test NVD Search"):
            if test_keyword:
                with st.spinner("Searching NVD..."):
                    results, total = search_nvd(test_keyword, max_results=5, lookback_months=lookback_months)
                    if results:
                        st.success(f"Found {total} total CVEs. First 5:")
                        for r in results:
                            st.write(f"- {r['cve']}: {r['description'][:100]}...")
                    else:
                        st.warning("No results. Try different keywords or increase lookback.")

    # ---------- Manual Asset Search (like the HTML tool) ----------
    st.markdown("## 🔎 Manual Asset Search (like the HTML tool)")
    with st.expander("Click to expand – Enter assets manually or upload a file", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            asset_text = st.text_area("Asset names (one per line)", height=150, key="manual_assets")
        with col2:
            uploaded_file_manual = st.file_uploader("Or upload Excel/CSV (first column used)", type=["xlsx", "csv"], key="manual_file")
            if uploaded_file_manual:
                try:
                    if uploaded_file_manual.name.endswith('.csv'):
                        df_manual = pd.read_csv(uploaded_file_manual)
                    else:
                        df_manual = pd.read_excel(uploaded_file_manual)
                    # Take first column as asset names
                    asset_names_from_file = df_manual.iloc[:, 0].dropna().astype(str).tolist()
                    asset_text = "\n".join(asset_names_from_file)
                    st.success(f"Loaded {len(asset_names_from_file)} assets from file.")
                except Exception as e:
                    st.error(f"Error reading file: {e}")

        if st.button("Find CVEs", key="manual_search_btn"):
            assets = [line.strip() for line in asset_text.split("\n") if line.strip()]
            if not assets:
                st.warning("Please enter at least one asset name.")
            else:
                with st.spinner("Searching NVD..."):
                    df_vulns, debug_info = manual_asset_search(assets, lookback_months=lookback_months)

                # Display debug info
                with st.expander("🔍 Search Query Debug (manual)"):
                    for name, query, count in debug_info:
                        st.write(f"**{name}**: `{query}` → {count} results")
                    st.caption("If a query returns zero results, try simplifying the query or increasing lookback.")

                if df_vulns.empty:
                    st.warning("No vulnerabilities found for the entered assets.")
                else:
                    st.success(f"Found {len(df_vulns)} vulnerabilities for {len(assets)} assets.")

                    # Summary stats
                    total = len(df_vulns)
                    critical = len(df_vulns[df_vulns["cvss_score"] >= 9.0])
                    high = len(df_vulns[(df_vulns["cvss_score"] >= 7.0) & (df_vulns["cvss_score"] < 9.0)])
                    assets_affected = df_vulns["asset"].nunique()
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Total CVEs", total)
                    with col2:
                        st.metric("Critical", critical)
                    with col3:
                        st.metric("High", high)
                    with col4:
                        st.metric("Assets Affected", assets_affected)

                    # Severity distribution chart (doughnut)
                    severity_counts = {
                        "Critical": critical,
                        "High": high,
                        "Medium": len(df_vulns[(df_vulns["cvss_score"] >= 4.0) & (df_vulns["cvss_score"] < 7.0)]),
                        "Low": len(df_vulns[df_vulns["cvss_score"] < 4.0])
                    }
                    fig = px.pie(
                        names=list(severity_counts.keys()),
                        values=list(severity_counts.values()),
                        title="Severity Distribution",
                        color=list(severity_counts.keys()),
                        color_discrete_map={"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#10b981"}
                    )
                    fig.update_traces(textposition='inside', textinfo='percent+label', hole=0.4)
                    st.plotly_chart(fig, use_container_width=True)

                    # Table of results
                    st.subheader("Vulnerability Details")
                    display_df = df_vulns[["asset", "cve", "cvss_score", "epss", "kev", "description"]].copy()
                    display_df["cvss_score"] = pd.to_numeric(display_df["cvss_score"], errors="coerce").round(1)
                    display_df["epss"] = pd.to_numeric(display_df["epss"], errors="coerce").round(4)
                    display_df["kev"] = display_df["kev"].apply(lambda x: "Yes" if x else "No")
                    st.dataframe(display_df, use_container_width=True)

    # ---------- Main Analysis (with column mapping) ----------
    st.markdown("## 📊 Detailed Asset Analysis (with column mapping)")
    uploaded_file = st.file_uploader("Choose Excel/CSV file", type=["xlsx", "csv"], key="main_file")
    if uploaded_file:
        try:
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)

            st.success(f"Loaded {len(df)} rows.")
            st.dataframe(df.head())

            # Column mapping
            st.subheader("Map Columns to Asset Fields")
            col_map = {}
            cols = df.columns.tolist()
            with st.form("column_mapping"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    col_map["asset_name"] = st.selectbox("Asset Name", ["-- None --"] + cols, index=0)
                    col_map["vendor"] = st.selectbox("Vendor (optional)", ["-- None --"] + cols, index=0)
                with col2:
                    col_map["asset_type"] = st.selectbox("Asset Type (optional)", ["-- None --"] + cols, index=0)
                    col_map["model"] = st.selectbox("Model (optional)", ["-- None --"] + cols, index=0)
                submit = st.form_submit_button("Analyze Assets")

            if submit:
                col_map = {k: v for k, v in col_map.items() if v != "-- None --"}
                if "asset_name" not in col_map:
                    st.error("Asset Name is required for analysis.")
                    return

                with st.spinner("Analyzing assets for vulnerabilities (this may take a few minutes)..."):
                    df_vulns, debug_info = analyze_assets(df, col_map, lookback_months=lookback_months)
                    st.session_state.vuln_df = df_vulns
                    st.session_state.asset_df = df
                    st.session_state.asset_count = len(df)
                    st.session_state.debug_info = debug_info
                    # Create a context string for the chatbot
                    asset_str = df[list(col_map.values())].head(20).to_string()
                    st.session_state.asset_context = f"Assets ({len(df)} rows):\n{asset_str}\n\nVulnerabilities found: {len(df_vulns)}"
                    if not df_vulns.empty:
                        st.session_state.asset_context += f"\nTop CVEs:\n{df_vulns[['cve','cvss_score','kev','description']].head(10).to_string()}"

                # Debug expander
                with st.expander("🔍 Search Query Debug (mapped assets)"):
                    for name, query, count in debug_info:
                        st.write(f"**{name}**: `{query}` → {count} results")
                    st.caption("If a query returns zero results, try simplifying the query (use fewer terms) or increasing the lookback months.")

                if df_vulns.empty:
                    st.warning("No vulnerabilities found. Check the debug info to see which queries returned zero results. You can also use the manual test search in the sidebar to experiment.")
                else:
                    with st.spinner("Generating threat summary..."):
                        summary = generate_threat_summary(df_vulns, len(df))
                        st.subheader("📊 Threat Landscape Summary")
                        st.write(summary)

                    # Dashboards
                    st.subheader("📈 Vulnerability Dashboard")
                    # CVSS Distribution
                    fig1 = px.histogram(df_vulns, x="cvss_score", nbins=20, title="CVSS Score Distribution")
                    st.plotly_chart(fig1, use_container_width=True)

                    # Risk level pie chart
                    df_vulns["risk_level"] = pd.cut(df_vulns["cvss_score"], bins=[0, 4, 7, 9, 10], labels=["Low", "Medium", "High", "Critical"])
                    risk_counts = df_vulns["risk_level"].value_counts().reset_index()
                    fig2 = px.pie(risk_counts, values="count", names="risk_level", title="Risk Level Distribution")
                    st.plotly_chart(fig2, use_container_width=True)

                    # Top affected assets
                    top_assets = df_vulns["asset"].value_counts().head(10).reset_index()
                    fig3 = px.bar(top_assets, x="asset", y="count", title="Top 10 Affected Assets")
                    st.plotly_chart(fig3, use_container_width=True)

                    # Table of top CVEs
                    st.subheader("Top 10 Critical CVEs")
                    top_cves = df_vulns.nlargest(10, "cvss_score")[["cve", "cvss_score", "epss", "kev", "description", "asset"]]
                    st.dataframe(top_cves)

        except Exception as e:
            st.error(f"Error processing file: {e}")

    # Chatbot section
    st.markdown("---")
    st.subheader("💬 Ask the AI Analyst")
    st.markdown("Ask questions about the assets, vulnerabilities, or any related threats.")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Ask a question..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                context = st.session_state.get("asset_context", "No assets uploaded yet.")
                answer = hf_chat(prompt, context)
                st.markdown(answer)
                st.session_state.messages.append({"role": "assistant", "content": answer})

if __name__ == "__main__":
    main()
