import streamlit as st
import pandas as pd
import requests
import time
from io import BytesIO
import plotly.graph_objects as go

# -------------------------------
# Page configuration
st.set_page_config(page_title="CVE Risk Dashboard", layout="wide")
st.title("🛡️ VulnRisk Dashboard")
st.markdown("Powered by **NIST NVD v2.0** and **Hugging Face AI**")

# -------------------------------
# Session state initialization
if "results" not in st.session_state:
    st.session_state.results = []
if "hf_token" not in st.session_state:
    st.session_state.hf_token = ""
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "assets_loaded" not in st.session_state:
    st.session_state.assets_loaded = False

# -------------------------------
# Sidebar: NVD API settings
with st.sidebar:
    st.header("NVD API Configuration")
    nvd_api_key = st.text_input("NVD API Key (optional)", type="password",
                                help="Increases rate limit to 50 requests per 30 seconds")
    st.markdown("---")
    st.header("Hugging Face AI Assistant")
    hf_token = st.text_input("Hugging Face API Token", type="password",
                             value=st.session_state.hf_token,
                             help="Get token at huggingface.co/settings/tokens")
    if st.button("Save HF Token"):
        st.session_state.hf_token = hf_token
        st.success("Token saved!")
    model_name = st.selectbox("Model", [
        "mistralai/Mistral-7B-Instruct-v0.2",
        "HuggingFaceH4/zephyr-7b-beta",
        "google/flan-t5-xl"
    ], index=0)

# -------------------------------
# Main area: input panel
st.header("🔍 Vulnerability Assessment")
col1, col2 = st.columns(2)
with col1:
    asset_input = st.text_area("Manual Asset List",
                               "apache log4j\nwindows server 2019",
                               height=150)
with col2:
    uploaded_file = st.file_uploader("Import from Excel or CSV",
                                     type=["csv", "xlsx", "xls"])
    if uploaded_file:
        try:
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            assets_from_file = df.iloc[:, 0].dropna().astype(str).tolist()
            asset_input = "\n".join(assets_from_file)
            st.success(f"Loaded {len(assets_from_file)} assets")
        except Exception as e:
            st.error(f"Error reading file: {e}")

# Date range
col3, col4 = st.columns(2)
with col3:
    start_date = st.date_input("Published Start Date", value=None)
with col4:
    end_date = st.date_input("Published End Date", value=None)

# Search button
if st.button("🔍 Find CVEs", type="primary"):
    assets = [a.strip() for a in asset_input.split("\n") if a.strip()]
    if not assets:
        st.error("Please enter at least one asset.")
    else:
        with st.spinner("Querying NVD..."):
            all_cves = []
            progress_bar = st.progress(0)
            for i, asset in enumerate(assets):
                url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    "keywordSearch": asset,
                    "resultsPerPage": 20
                }
                if start_date:
                    params["pubStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
                if end_date:
                    params["pubEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999Z")
                headers = {}
                if nvd_api_key:
                    headers["apiKey"] = nvd_api_key
                try:
                    resp = requests.get(url, params=params, headers=headers, timeout=30)
                    if resp.status_code == 403:
                        st.error(f"API key invalid or rate limited for asset {asset}. Skipping.")
                        continue
                    elif resp.status_code != 200:
                        st.error(f"Error {resp.status_code} for asset {asset}: {resp.text[:200]}")
                        continue
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    for vuln in vulnerabilities:
                        cve = vuln["cve"]
                        cve_id = cve["id"]
                        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                                    "No description")
                        metrics = cve.get("metrics", {})
                        cvss_data = None
                        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                            cvss_data = metrics["cvssMetricV31"][0].get("cvssData")
                        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                            cvss_data = metrics["cvssMetricV30"][0].get("cvssData")
                        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                            cvss_data = metrics["cvssMetricV2"][0].get("cvssData")
                        if cvss_data:
                            score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "")
                            if not severity:
                                if score >= 7.0:
                                    severity = "HIGH"
                                elif score >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"
                            vector = cvss_data.get("vectorString", "")
                        else:
                            score = None
                            severity = "N/A"
                            vector = ""
                        sev_class = {
                            "CRITICAL": "severity-critical",
                            "HIGH": "severity-high",
                            "MEDIUM": "severity-medium",
                            "LOW": "severity-low"
                        }.get(severity.upper(), "")
                        refs = cve.get("references", [])
                        mitigation_url = None
                        for ref in refs:
                            if "tags" in ref and "Vendor Advisory" in ref["tags"]:
                                mitigation_url = ref["url"]
                                break
                        if not mitigation_url and refs:
                            mitigation_url = refs[0]["url"]
                        all_cves.append({
                            "asset": asset,
                            "cveId": cve_id,
                            "description": desc,
                            "severity": severity.capitalize(),
                            "score": score,
                            "vector": vector,
                            "sevClass": sev_class,
                            "mitigationUrl": mitigation_url
                        })
                except Exception as e:
                    st.error(f"Error fetching for {asset}: {e}")
                time.sleep(0.6 if nvd_api_key else 6.0)
                progress_bar.progress((i + 1) / len(assets))
            st.session_state.results = all_cves
            st.session_state.assets_loaded = True
            st.success(f"Found {len(all_cves)} CVEs across {len(assets)} assets.")
            st.rerun()

# -------------------------------
# Display results if available
if st.session_state.assets_loaded and st.session_state.results:
    results = st.session_state.results
    df_results = pd.DataFrame(results)

    total = len(results)
    critical = sum(1 for r in results if r["severity"] == "Critical")
    high = sum(1 for r in results if r["severity"] == "High")
    assets_count = len(set(r["asset"] for r in results))

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total CVEs", total)
    col2.metric("Critical", critical)
    col3.metric("High", high)
    col4.metric("Assets Scanned", assets_count)

    severity_counts = {
        "Critical": critical,
        "High": high,
        "Medium": sum(1 for r in results if r["severity"] == "Medium"),
        "Low": sum(1 for r in results if r["severity"] == "Low"),
        "Unknown": sum(1 for r in results if r["severity"] not in ["Critical", "High", "Medium", "Low"])
    }
    fig = go.Figure(data=[go.Pie(labels=list(severity_counts.keys()),
                                 values=list(severity_counts.values()),
                                 hole=0.7,
                                 marker_colors=["#7f1d1d", "#991b1b", "#b45309", "#065f46", "#64748b"])])
    fig.update_layout(title="Severity Distribution", height=400)
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Discovered Vulnerabilities")
    display_df = df_results[["asset", "cveId", "severity", "score", "vector", "description", "mitigationUrl"]].copy()
    display_df["CVE Link"] = display_df["cveId"].apply(lambda x: f"https://nvd.nist.gov/vuln/detail/{x}")
    display_df["Mitigation"] = display_df["mitigationUrl"].apply(lambda x: f"[Advisory]({x})" if x else "N/A")
    display_df.rename(columns={
        "asset": "Asset",
        "cveId": "CVE ID",
        "severity": "Risk",
        "score": "CVSS Score",
        "vector": "Vector",
        "description": "Description"
    }, inplace=True)
    st.dataframe(
        display_df[["Asset", "CVE ID", "Risk", "CVSS Score", "Vector", "Description", "Mitigation"]],
        use_container_width=True,
        height=400,
        column_config={
            "CVE ID": st.column_config.LinkColumn("CVE ID", display_text="(.*)"),
            "Mitigation": st.column_config.LinkColumn("Mitigation", display_text="Advisory"),
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "CVSS Score": st.column_config.NumberColumn("CVSS Score", format="%.1f"),
            "Description": st.column_config.TextColumn("Description", width="large")
        }
    )

# -------------------------------
# Chatbot Interface
st.header("🤖 AI Security Assistant")
st.markdown("Ask questions about CVEs, remediation, or risk analysis. The assistant can use your current dashboard data as context.")

for msg in st.session_state.chat_history:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Ask about vulnerabilities..."):
    st.session_state.chat_history.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    context = ""
    if st.session_state.results:
        critical_high = [r for r in st.session_state.results if r["severity"] in ["Critical", "High"]]
        if critical_high:
            context = "Current dashboard shows these critical/high CVEs:\n"
            for c in critical_high[:5]:
                context += f"- {c['cveId']} ({c['severity']}): {c['description'][:120]}...\n"
            context += "\n"

    system = "You are a cybersecurity expert specializing in CVE analysis, risk scoring, and mitigation. Provide concise, actionable advice."
    if "mistral" in model_name or "zephyr" in model_name:
        full_prompt = f"<s>[INST] {system} {context} {prompt} [/INST]"
    else:
        full_prompt = f"{system}\n{context}User: {prompt}\nAssistant:"

    if not st.session_state.hf_token:
        response = "⚠️ Please provide a Hugging Face API token in the sidebar to enable the AI assistant."
    else:
        with st.spinner("Thinking..."):
            try:
                # NEW HUGGING FACE ROUTER ENDPOINT
                api_url = f"https://router.huggingface.co/hf-inference/models/{model_name}"
                headers = {"Authorization": f"Bearer {st.session_state.hf_token}"}
                payload = {
                    "inputs": full_prompt,
                    "parameters": {"max_new_tokens": 500, "temperature": 0.7, "return_full_text": False}
                }
                resp = requests.post(api_url, headers=headers, json=payload, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and data and "generated_text" in data[0]:
                        reply = data[0]["generated_text"]
                    elif isinstance(data, dict) and "generated_text" in data:
                        reply = data["generated_text"]
                    else:
                        reply = str(data)[:500]
                else:
                    reply = f"❌ API error {resp.status_code}: {resp.text[:200]}"
            except Exception as e:
                reply = f"❌ Error: {e}"

    st.session_state.chat_history.append({"role": "assistant", "content": reply})
    with st.chat_message("assistant"):
        st.markdown(reply)

if st.session_state.results and st.button("📊 Analyze my CVEs"):
    critical_high = [r for r in st.session_state.results if r["severity"] in ["Critical", "High"]]
    context = "Current dashboard shows these critical/high CVEs:\n"
    for c in critical_high[:10]:
        context += f"- {c['cveId']} ({c['severity']}): {c['description'][:120]}...\n"
    prompt = f"Please analyze the current vulnerabilities from my dashboard: I have {len(st.session_state.results)} total CVEs (Critical: {sum(1 for r in st.session_state.results if r['severity']=='Critical')}, High: {sum(1 for r in st.session_state.results if r['severity']=='High')}). Give me top 3 remediation priorities and risk summary."

    st.session_state.chat_history.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.spinner("Analyzing..."):
        try:
            api_url = f"https://router.huggingface.co/hf-inference/models/{model_name}"
            headers = {"Authorization": f"Bearer {st.session_state.hf_token}"}
            payload = {
                "inputs": prompt,
                "parameters": {"max_new_tokens": 500, "temperature": 0.7, "return_full_text": False}
            }
            resp = requests.post(api_url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data and "generated_text" in data[0]:
                    reply = data[0]["generated_text"]
                elif isinstance(data, dict) and "generated_text" in data:
                    reply = data["generated_text"]
                else:
                    reply = str(data)[:500]
            else:
                reply = f"❌ API error {resp.status_code}: {resp.text[:200]}"
        except Exception as e:
            reply = f"❌ Error: {e}"

    st.session_state.chat_history.append({"role": "assistant", "content": reply})
    with st.chat_message("assistant"):
        st.markdown(reply)
    st.rerun()

st.markdown("---")
st.markdown("Data from NIST NVD. AI responses are generated and should be verified.")
