import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
import json
import uuid
import groq
from typing import Dict, List, Optional, Tuple

# ---------- Page Configuration ----------
st.set_page_config(
    page_title="Vuln Intelligence Dashboard",
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
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except:
    GROQ_API_KEY = None
    st.warning("Groq API key not found. LLM features will be disabled.")

# ---------- API Key Status ----------
with st.sidebar:
    if NVD_API_KEY:
        st.success("✅ NVD API key loaded")
    else:
        st.info("ℹ️ No NVD API key – using public rate limits.")
    if not GROQ_API_KEY:
        st.error("❌ Groq API key required for AI Agent.")

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
def search_nvd(keyword: str, start_date: datetime, end_date: datetime, max_results: int = 50) -> List[Dict]:
    """Basic NVD keyword search (returns only CVE ID and description)."""
    max_results = int(max_results)
    results = []
    start_index = 0
    while len(results) < max_results:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
        pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999Z")
        params = {
            "keywordSearch": keyword,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
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
                total = data.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total:
                    break
                time.sleep(0.2)  # avoid rate limits
            elif resp.status_code == 404:
                st.warning(f"NVD search returned 404 – no results for '{keyword}'.")
                break
            else:
                st.error(f"NVD search error {resp.status_code}")
                break
        except Exception as e:
            st.error(f"Search error: {e}")
            break
    return results[:max_results]

def enrich_cve(cve_id: str, kev_list: List[Dict]) -> Dict:
    """Fetch and enrich a single CVE with EPSS, KEV, and past likelihood."""
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
            "description": "Search for vulnerabilities by keyword and return fully enriched data including CVSS score, EPSS probability, KEV status, and past likelihood. This is the primary tool for answering general questions about vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "The search term (e.g., 'Cisco', 'Apache', 'RCE')."
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of CVEs to return (default 10)."
                    }
                },
                "required": ["keyword"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_details",
            "description": "Get full details of a specific CVE including CVSS score, description, EPSS probability, KEV status, and past likelihood.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE ID, e.g., 'CVE-2023-12345'."
                    }
                },
                "required": ["cve_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_kev_catalog",
            "description": "List vulnerabilities that are in the CISA Known Exploited Vulnerabilities (KEV) catalog. Returns up to 20 entries.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    }
]

def execute_tool(tool_name: str, arguments: Dict) -> str:
    """Execute the tool and return a string result."""
    if tool_name == "search_vulnerabilities":
        keyword = arguments["keyword"]
        max_results = arguments.get("max_results", 10)
        try:
            max_results = int(max_results)
        except:
            max_results = 10

        # First, get basic list from NVD (last year)
        basic_results = search_nvd(keyword, datetime.now() - timedelta(days=365), datetime.now(), max_results)
        if not basic_results:
            return f"No vulnerabilities found for '{keyword}'."

        # Fetch KEV catalog once
        kev_list = fetch_kev_catalog()

        enriched = []
        for item in basic_results[:max_results]:
            cve_id = item["cve"]
            enriched_item = enrich_cve(cve_id, kev_list)
            if enriched_item:
                enriched.append(enriched_item)

        if not enriched:
            return f"Could not enrich any CVEs for '{keyword}'."

        # Return as JSON
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

    else:
        return f"Unknown tool: {tool_name}"

# ---------- LLM Agent Loop ----------
def agent_query(user_message: str, conversation_history: List[Dict]) -> Tuple[str, List[Dict]]:
    messages = []
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_message})

    system_prompt = {
        "role": "system",
        "content": """You are a cybersecurity vulnerability analyst. You have access to the following tools:

- search_vulnerabilities: Use this to search for vulnerabilities by keyword (e.g., "Cisco switches"). It returns a list of CVEs with CVSS scores, EPSS probabilities, KEV status, and past likelihood. This is your primary tool for answering general questions.

- get_cve_details: Use this when you need detailed information about a specific CVE ID.

- list_kev_catalog: Use this to list all CVEs in the CISA KEV catalog.

When answering a question, use the appropriate tool(s) to gather data. If the user asks for a summary or analysis, first retrieve the data, then provide a concise, prioritized summary highlighting the most critical vulnerabilities (e.g., those with high CVSS, high EPSS, or in KEV). Be helpful and actionable."""
    }
    if not messages or messages[0].get("role") != "system":
        messages.insert(0, system_prompt)

    max_iterations = 10  # allow deeper reasoning if needed
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
    st.title("🛡️ Vulnerability Intelligence Dashboard")
    st.markdown("Aggregate **CVSS**, **EPSS**, **CISA KEV**, and compute **Past Likelihood (LEV)**. Powered by open‑source LLM (Groq).")

    mode = st.sidebar.radio("Select Mode", ["Single CVE Lookup", "Search & Dashboard", "AI Agent"])

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

    elif mode == "AI Agent":
        st.header("🤖 AI Vulnerability Agent")
        st.markdown("Ask anything about vulnerabilities. The agent will fetch data from NVD, EPSS, and CISA KEV as needed.")

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
