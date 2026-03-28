import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
import json
import re
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
    # Ensure max_results is integer (in case it's passed as string)
    max_results = int(max_results)

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

# ---------- LLM Agent Tools ----------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_cves",
            "description": "Search for vulnerabilities by keyword. Returns a list of CVE IDs and brief info.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "The search term (e.g., 'Apache', 'RCE')."
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
    if tool_name == "search_cves":
        keyword = arguments["keyword"]
        max_results = arguments.get("max_results", 10)
        # Ensure max_results is integer
        try:
            max_results = int(max_results)
        except:
            max_results = 10
        results = search_nvd(keyword, datetime.now() - timedelta(days=365), datetime.now(), max_results)
        if not results:
            return f"No CVEs found for '{keyword}'."
        # Return only essential fields to keep it concise
        simplified = [{"cve": r["cve"], "description": r["description"][:200]} for r in results]
        return json.dumps(simplified, indent=2)

    elif tool_name == "get_cve_details":
        cve_id = arguments["cve_id"]
        nvd = fetch_nvd_cve(cve_id)
        if not nvd:
            return f"CVE {cve_id} not found."
        epss = fetch_epss(cve_id)
        kev_list = fetch_kev_catalog()
        in_kev = is_in_kev(cve_id, kev_list)
        past_likelihood = get_past_likelihood(nvd["exploitability_score"], in_kev)
        result = {
            "cve": cve_id,
            "cvss_score": nvd["cvss_score"],
            "description": nvd["description"],
            "epss": epss,
            "kev": in_kev,
            "past_likelihood": past_likelihood
        }
        return json.dumps(result, indent=2)

    elif tool_name == "list_kev_catalog":
        kev_list = fetch_kev_catalog()
        if not kev_list:
            return "No KEV entries found."
        # Return first 20 for brevity
        short_list = [{"cve": item.get("cveID"), "description": item.get("shortDescription", "")[:100]} for item in kev_list[:20]]
        return json.dumps(short_list, indent=2)

    else:
        return f"Unknown tool: {tool_name}"

# ---------- LLM Agent Loop ----------
def agent_query(user_message: str, conversation_history: List[Dict]) -> Tuple[str, List[Dict]]:
    """
    Process a user message using the agent loop.
    Returns the final assistant answer and updated conversation history.
    """
    # System prompt with tool definitions
    system_prompt = """You are a cybersecurity vulnerability analyst. You have access to the following tools:

<tools>
{
  "name": "search_cves",
  "description": "Search for vulnerabilities by keyword. Returns a list of CVE IDs and brief info.",
  "parameters": {
    "keyword": "string (required)",
    "max_results": "integer (optional, default 10)"
  }
}
{
  "name": "get_cve_details",
  "description": "Get full details of a specific CVE including CVSS score, description, EPSS probability, KEV status, and past likelihood.",
  "parameters": {
    "cve_id": "string (required)"
  }
}
{
  "name": "list_kev_catalog",
  "description": "List vulnerabilities that are in the CISA Known Exploited Vulnerabilities (KEV) catalog. Returns up to 20 entries.",
  "parameters": {}
}
</tools>

When you need to use a tool, respond with a JSON object in the following format:
{"tool": "<tool_name>", "arguments": {"param1": "value1", ...}}

If you have enough information to answer the user, respond with a plain text answer (no JSON). Do not add any extra text outside the JSON when using a tool.

Think step by step. Use tools only when necessary. Be concise but thorough.
"""

    # Build messages list
    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_message})

    max_iterations = 5
    iteration = 0

    while iteration < max_iterations:
        # Call Groq – using stable production model (llama-3.3-70b-versatile)
        client = groq.Groq(api_key=GROQ_API_KEY)
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",   # Production model
                messages=messages,
                temperature=0.2,
                max_tokens=1024,
            )
            assistant_message = response.choices[0].message.content
        except Exception as e:
            return f"Error calling LLM: {e}", conversation_history

        # Try to parse as JSON tool call
        try:
            parsed = json.loads(assistant_message)
            if isinstance(parsed, dict) and "tool" in parsed and "arguments" in parsed:
                tool_name = parsed["tool"]
                arguments = parsed["arguments"]
                # Execute the tool
                tool_result = execute_tool(tool_name, arguments)
                # Add tool call and result to messages
                messages.append({"role": "assistant", "content": assistant_message})
                messages.append({"role": "tool", "content": tool_result})
                iteration += 1
                continue  # loop again
        except json.JSONDecodeError:
            pass

        # Not a tool call -> final answer
        # Append final answer to conversation history
        conversation_history.append({"role": "user", "content": user_message})
        conversation_history.append({"role": "assistant", "content": assistant_message})
        return assistant_message, conversation_history

    # If we exit loop without final answer, return last message
    final_message = "I'm sorry, I couldn't resolve your request. Please try again."
    conversation_history.append({"role": "user", "content": user_message})
    conversation_history.append({"role": "assistant", "content": final_message})
    return final_message, conversation_history

# ---------- Streamlit UI ----------
def main():
    st.title("🛡️ Vulnerability Intelligence Dashboard")
    st.markdown("Aggregate **CVSS**, **EPSS**, **CISA KEV**, and compute **Past Likelihood (LEV)**. Powered by open‑source LLM (Groq).")

    # Sidebar for mode selection
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

                        # Store data for chat agent if needed
                        st.session_state.last_data = {
                            "cve": cve_input,
                            "cvss": nvd["cvss_score"],
                            "epss": epss,
                            "kev": in_kev,
                            "lev": past_likelihood,
                            "desc": nvd["description"]
                        }

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
                        df = enrich_cve_data(cve_list)

                        # Display interactive table
                        st.subheader("📋 Vulnerability List")
                        st.dataframe(df, use_container_width=True)

                        # Visualizations
                        st.subheader("📈 Visualizations")
                        df_plot = df.copy()
                        df_plot["CVSS Score"] = pd.to_numeric(df_plot["CVSS Score"], errors="coerce")
                        df_plot["EPSS Probability"] = pd.to_numeric(df_plot["EPSS Probability"], errors="coerce")
                        df_plot = df_plot.dropna(subset=["CVSS Score"])

                        if not df_plot.empty:
                            fig1 = px.bar(
                                df_plot, x="CVE", y="CVSS Score",
                                color="Past Likelihood (LEV)",
                                title="CVSS Scores by Vulnerability",
                                labels={"CVSS Score": "CVSS v3 Score"},
                                height=500,
                            )
                            st.plotly_chart(fig1, use_container_width=True)

                            df_scatter = df_plot.dropna(subset=["EPSS Probability"])
                            if not df_scatter.empty:
                                fig2 = px.scatter(
                                    df_scatter, x="CVSS Score", y="EPSS Probability",
                                    hover_name="CVE", color="Past Likelihood (LEV)",
                                    title="Risk Matrix: CVSS vs EPSS",
                                    labels={"CVSS Score": "CVSS v3 Score", "EPSS Probability": "EPSS (Exploit Probability)"},
                                )
                                st.plotly_chart(fig2, use_container_width=True)

                            st.subheader("📊 Summary Statistics")
                            col1, col2, col3 = st.columns(3)
                            col1.metric("Avg CVSS Score", f"{df_plot['CVSS Score'].mean():.2f}")
                            col2.metric("Max CVSS Score", f"{df_plot['CVSS Score'].max():.2f}")
                            col3.metric("KEV Count", len(df[df["KEV"] == "Yes"]))

                        # Store data for chat agent if needed
                        st.session_state.last_data = df

    elif mode == "AI Agent":
        st.header("🤖 AI Vulnerability Agent")
        st.markdown("Ask anything about vulnerabilities. The agent will fetch data from NVD, EPSS, and CISA KEV as needed.")

        # Initialize conversation history in session state
        if "agent_messages" not in st.session_state:
            st.session_state.agent_messages = []  # list of {"role": "user"/"assistant", "content": ...}

        # Display chat history
        for msg in st.session_state.agent_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        # User input
        if prompt := st.chat_input("Ask a question..."):
            # Add user message to UI
            with st.chat_message("user"):
                st.markdown(prompt)

            # Process with agent
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    answer, new_history = agent_query(prompt, st.session_state.agent_messages)
                    st.markdown(answer)
                    # Update session state with the new history
                    st.session_state.agent_messages = new_history

if __name__ == "__main__":
    main()
