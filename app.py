import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
import json
import uuid
import groq
import base64
from typing import Dict, List, Optional, Tuple

# ---------- Page Configuration ----------
st.set_page_config(
    page_title="OT Vulnerability Intelligence Platform",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Load Secrets ----------
try:
    NVD_API_KEY = st.secrets.get("NVD_API_KEY", None)
except:
    NVD_API_KEY = None

try:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except:
    GROQ_API_KEY = None
    st.warning("Groq API key not found. LLM features will be disabled.")

# ---------- Custom CSS for Industrial Theme ----------
st.markdown("""
<style>
    /* Dark theme with industrial accents */
    .stApp {
        background-color: #0a0c10;
        color: #e0e0e0;
    }
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #4caf50, #ff9800);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
    }
    .ot-badge {
        background: #1e2a1f;
        color: #8bc34a;
        padding: 0.3rem 1rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
        display: inline-block;
    }
    .risk-critical { color: #f44336; font-weight: bold; }
    .risk-high { color: #ff9800; font-weight: bold; }
    .risk-medium { color: #ffc107; }
    .risk-low { color: #4caf50; }
    .asset-card {
        background: #1e1e2e;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border-left: 4px solid #ff9800;
    }
</style>
""", unsafe_allow_html=True)

# ---------- API Key Status ----------
with st.sidebar:
    st.markdown("### 🔧 Configuration")
    if NVD_API_KEY:
        st.success("✅ NVD API key loaded")
    else:
        st.info("ℹ️ No NVD API key – using public rate limits.")
    if not GROQ_API_KEY:
        st.error("❌ Groq API key required for AI Agent.")
    st.markdown("---")
    st.markdown("### 🏭 OT Community")
    st.markdown("Share your analysis: [Export Report](#)")

# ---------- Cached API Functions ----------
@st.cache_data(ttl=3600, show_spinner=False)
def fetch_nvd_cve(cve_id: str) -> Optional[Dict]:
    """Fetch a single CVE from NVD."""
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
    except Exception:
        pass
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

@st.cache_data(ttl=86400, show_spinner=False)
def fetch_ics_advisories() -> List[Dict]:
    """Fetch ICS-CERT advisories from CISA (JSON feed)."""
    url = "https://www.cisa.gov/sites/default/files/feeds/ics-advisories.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("advisories", [])
    except Exception:
        pass
    return []

def is_in_kev(cve_id: str, kev_list: List[Dict]) -> bool:
    for item in kev_list:
        if item.get("cveID") == cve_id:
            return True
    return False

def get_past_likelihood(exploitability_score, in_kev: bool) -> str:
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
def search_nvd(keyword: str, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None, max_results: int = 50) -> List[Dict]:
    """Search NVD with optional keyword and date range. If keyword contains OT terms, boost relevance."""
    max_results = int(max_results)
    results = []
    start_index = 0
    # Enhance keyword for OT context
    ot_terms = ["ics", "scada", "plc", "rtu", "hmi", "modbus", "opc", "profibus", "fieldbus"]
    if any(term in keyword.lower() for term in ot_terms):
        # Add "ics" to keyword to catch OT-specific CVEs
        keyword += " ics"

    while len(results) < max_results:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": min(50, max_results - len(results)),
        }
        if start_date:
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
        if end_date:
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999Z")

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
                total = data.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total:
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
    return results[:max_results]

def enrich_cve(cve_id: str, kev_list: List[Dict]) -> Dict:
    nvd = fetch_nvd_cve(cve_id)
    if not nvd:
        return None
    epss = fetch_epss(cve_id)
    in_kev = is_in_kev(cve_id, kev_list)
    past_likelihood = get_past_likelihood(nvd["exploitability_score"], in_kev)
    return {
        "cve": cve_id,
        "cvss_score": nvd["cvss_score"],
        "epss": epss,
        "kev": in_kev,
        "past_likelihood": past_likelihood,
        "description": nvd["description"]
    }

# ---------- LLM Agent Tools ----------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_vulnerabilities",
            "description": "Search for vulnerabilities by keyword, with optional OT focus. Returns enriched data (CVSS, EPSS, KEV).",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "Search term (e.g., 'Cisco', 'PLC', 'Modbus')."},
                    "max_results": {"type": "integer", "description": "Max CVEs to return (default 10)."}
                },
                "required": ["keyword"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_details",
            "description": "Get full details of a specific CVE.",
            "parameters": {
                "type": "object",
                "properties": {"cve_id": {"type": "string", "description": "CVE ID"}},
                "required": ["cve_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_kev_catalog",
            "description": "List CVEs in CISA KEV catalog.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_ics_advisories",
            "description": "Get recent ICS-CERT advisories (OT/ICS specific).",
            "parameters": {"type": "object", "properties": {}}
        }
    }
]

def execute_tool(tool_name: str, arguments: Dict) -> str:
    if tool_name == "search_vulnerabilities":
        keyword = arguments["keyword"]
        max_results = arguments.get("max_results", 10)
        try:
            max_results = int(max_results)
        except:
            max_results = 10
        basic_results = search_nvd(keyword, max_results=max_results)
        if not basic_results:
            return f"No vulnerabilities found for '{keyword}'."
        kev_list = fetch_kev_catalog()
        enriched = []
        for item in basic_results[:max_results]:
            enriched_item = enrich_cve(item["cve"], kev_list)
            if enriched_item:
                enriched.append(enriched_item)
        if not enriched:
            return f"Could not enrich CVEs for '{keyword}'."
        return json.dumps(enriched, indent=2)

    elif tool_name == "get_cve_details":
        cve_id = arguments["cve_id"]
        kev_list = fetch_kev_catalog()
        enriched = enrich_cve(cve_id, kev_list)
        if not enriched:
            return f"CVE {cve_id} not found."
        return json.dumps(enriched, indent=2)

    elif tool_name == "list_kev_catalog":
        kev_list = fetch_kev_catalog()
        if not kev_list:
            return "No KEV entries found."
        short_list = [{"cve": item.get("cveID"), "description": item.get("shortDescription", "")[:100]} for item in kev_list[:20]]
        return json.dumps(short_list, indent=2)

    elif tool_name == "get_ics_advisories":
        advisories = fetch_ics_advisories()
        if not advisories:
            return "No ICS advisories found."
        short_list = [{"title": a.get("title"), "id": a.get("icsa"), "date": a.get("releaseDate")} for a in advisories[:10]]
        return json.dumps(short_list, indent=2)

    else:
        return f"Unknown tool: {tool_name}"

def agent_query(user_message: str, conversation_history: List[Dict]) -> Tuple[str, List[Dict]]:
    messages = []
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_message})

    system_prompt = {
        "role": "system",
        "content": """You are an OT/ICS cybersecurity analyst. You have access to NVD, EPSS, CISA KEV, and ICS-CERT advisories. Use tools to gather data. When answering, consider OT/ICS implications: safety, operational impact, and typical industrial network constraints. Provide actionable advice for asset owners."""
    }
    if not messages or messages[0].get("role") != "system":
        messages.insert(0, system_prompt)

    max_iterations = 10
    iteration = 0

    while iteration < max_iterations:
        client = groq.Groq(api_key=GROQ_API_KEY)
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.2,
                max_tokens=1024,
            )
            assistant_message = response.choices[0].message
        except Exception as e:
            return f"Error calling LLM: {e}", conversation_history

        if assistant_message.tool_calls:
            messages.append(assistant_message)
            for tool_call in assistant_message.tool_calls:
                tool_name = tool_call.function.name
                arguments = json.loads(tool_call.function.arguments)
                tool_result = execute_tool(tool_name, arguments)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_result,
                })
            iteration += 1
            continue
        else:
            final_answer = assistant_message.content
            conversation_history.append({"role": "user", "content": user_message})
            conversation_history.append({"role": "assistant", "content": final_answer})
            return final_answer, conversation_history

    final_message = "I'm sorry, I couldn't resolve your request. Please try again."
    conversation_history.append({"role": "user", "content": user_message})
    conversation_history.append({"role": "assistant", "content": final_message})
    return final_message, conversation_history

# ---------- Streamlit UI ----------
def main():
    st.markdown('<div class="main-header">🏭 OT Vulnerability Intelligence Platform</div>', unsafe_allow_html=True)
    st.markdown("Powered by **NVD**, **EPSS**, **CISA KEV**, **ICS‑CERT** — with AI insights from Groq (Llama 3.3 70B)")

    # Sidebar for mode selection
    mode = st.sidebar.radio("Select Mode", ["Single CVE Lookup", "Search & Dashboard", "OT Asset Risk Analyzer", "AI Agent"])

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

    elif mode == "Search & Dashboard":
        st.header("🔎 Search & Dashboard")
        col1, col2, col3 = st.columns(3)
        with col1:
            keyword = st.text_input("Search Keyword (e.g., 'PLC', 'Modbus', 'Cisco')")
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
                        kev_list = fetch_kev_catalog()
                        enriched = []
                        for item in cve_list:
                            enriched_item = enrich_cve(item["cve"], kev_list)
                            if enriched_item:
                                enriched.append(enriched_item)
                        df = pd.DataFrame(enriched)

                        st.subheader("📋 Vulnerability List")
                        st.dataframe(df, use_container_width=True)

                        st.subheader("📈 Visualizations")
                        df_plot = df.copy()
                        df_plot["cvss_score"] = pd.to_numeric(df_plot["cvss_score"], errors="coerce")
                        df_plot = df_plot.dropna(subset=["cvss_score"])

                        if not df_plot.empty:
                            fig1 = px.bar(
                                df_plot, x="cve", y="cvss_score",
                                color="past_likelihood",
                                title="CVSS Scores by Vulnerability",
                                labels={"cvss_score": "CVSS v3 Score", "cve": "CVE"},
                                height=500,
                            )
                            st.plotly_chart(fig1, use_container_width=True)

                            st.subheader("📊 Summary Statistics")
                            col1, col2, col3 = st.columns(3)
                            col1.metric("Avg CVSS Score", f"{df_plot['cvss_score'].mean():.2f}")
                            col2.metric("Max CVSS Score", f"{df_plot['cvss_score'].max():.2f}")
                            col3.metric("KEV Count", len(df[df["kev"] == True]))

    elif mode == "OT Asset Risk Analyzer":
        st.header("🏭 OT Asset Risk Analyzer")
        st.markdown("Enter your OT assets (one per line) to discover vulnerabilities affecting them.")
        assets_text = st.text_area("Assets (e.g., 'Siemens S7-1200', 'Modicon M241', 'Rockwell ControlLogix')", height=150)
        if st.button("Analyze OT Assets", type="primary"):
            if not assets_text.strip():
                st.warning("Please enter at least one asset.")
            else:
                assets = [a.strip() for a in assets_text.split('\n') if a.strip()]
                all_results = []
                for asset in assets:
                    with st.spinner(f"Searching for {asset}..."):
                        cve_list = search_nvd(asset, max_results=10)
                        kev_list = fetch_kev_catalog()
                        for item in cve_list:
                            enriched = enrich_cve(item["cve"], kev_list)
                            if enriched:
                                enriched["asset"] = asset
                                all_results.append(enriched)
                if not all_results:
                    st.info("No vulnerabilities found for the provided assets.")
                else:
                    df = pd.DataFrame(all_results)
                    st.subheader("🔍 Vulnerabilities by Asset")
                    # Add OT‑specific risk score
                    df["OT_Risk"] = df.apply(lambda row: "Critical" if row["kev"] else ("High" if row["cvss_score"] > 7.0 else "Medium"), axis=1)
                    st.dataframe(df, use_container_width=True)
                    # Generate LLM summary
                    if GROQ_API_KEY:
                        prompt = f"Analyze these OT vulnerabilities for assets {assets}. Summarize the highest risks and provide mitigation steps:\n{df.to_string()}"
                        with st.spinner("Generating OT risk summary..."):
                            summary = agent_query(prompt, [])[0]
                            st.markdown("### 🤖 OT Risk Summary")
                            st.write(summary)

    else:  # AI Agent
        st.header("🤖 OT Vulnerability Agent")
        st.markdown("Ask anything about OT/ICS vulnerabilities. The agent can search NVD, fetch ICS advisories, and analyze risk.")

        if "agent_messages" not in st.session_state:
            st.session_state.agent_messages = []

        for msg in st.session_state.agent_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        if prompt := st.chat_input("Ask a question..."):
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    answer, new_history = agent_query(prompt, st.session_state.agent_messages)
                    st.markdown(answer)
                    st.session_state.agent_messages = new_history

if __name__ == "__main__":
    main()
