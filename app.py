import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
import json
import groq
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
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except:
    GROQ_API_KEY = None

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

def search_nvd(keyword: str, max_results: int = 20, lookback_months: int = 24) -> List[Dict]:
    """Search NVD for CVEs matching keyword."""
    start_date = datetime.now() - timedelta(days=lookback_months * 30)
    end_date = datetime.now()
    results = []
    start_index = 0
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
                if start_index >= data.get("totalResults", 0):
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
    """Analyze each asset using the column mapping."""
    kev_list = fetch_kev_catalog()
    all_vulns = []
    for _, row in df.iterrows():
        # Build query from mapped columns
        terms = []
        for field in ["asset_name", "asset_type", "vendor", "model", "firmware"]:
            col = column_map.get(field)
            if col and pd.notna(row[col]) and str(row[col]).strip():
                terms.append(str(row[col]).strip())
        if not terms:
            continue
        query = " ".join(terms)
        cve_list = search_nvd(query, max_results=10, lookback_months=lookback_months)
        for cve_info in cve_list:
            enriched = enrich_cve(cve_info["cve"], kev_list)
            if enriched:
                enriched["asset"] = row.get(column_map.get("asset_name", ""), "Unknown")
                enriched["asset_type"] = row.get(column_map.get("asset_type", ""), "")
                enriched["vendor"] = row.get(column_map.get("vendor", ""), "")
                enriched["model"] = row.get(column_map.get("model", ""), "")
                all_vulns.append(enriched)
    df_vulns = pd.DataFrame(all_vulns)
    return df_vulns

def generate_threat_summary(df_vulns, assets_count):
    """Generate AI summary of the threat landscape."""
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
    prompt = f"""
You are a cybersecurity analyst. Based on the following vulnerability data from NVD, EPSS, and CISA KEV, provide a concise summary of the threat landscape for the uploaded OT assets.

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

Also consider any relevant ICS‑CERT advisories that might affect these assets (not included here, but the agent can fetch them). 
Write a brief summary highlighting the most critical risks and recommended immediate actions.
"""
    if not GROQ_API_KEY:
        return "Groq API key not configured. Cannot generate summary."
    client = groq.Groq(api_key=GROQ_API_KEY)
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=800,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error generating summary: {e}"

# ---------- AI Agent Tools ----------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_vulnerabilities",
            "description": "Search for vulnerabilities by keyword in NVD.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "Search term (e.g., 'Siemens S7-1200')"},
                    "max_results": {"type": "integer", "description": "Max CVEs to return (default 10)"}
                },
                "required": ["keyword"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_details",
            "description": "Get full details of a specific CVE including CVSS, EPSS, KEV status.",
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
            "description": "Get recent ICS-CERT advisories.",
            "parameters": {"type": "object", "properties": {}}
        }
    }
]

def execute_tool(tool_name: str, arguments: Dict) -> str:
    """Execute tool and return result as string."""
    if tool_name == "search_vulnerabilities":
        keyword = arguments["keyword"]
        max_results = arguments.get("max_results", 10)
        try:
            max_results = int(max_results)
        except:
            max_results = 10
        results = search_nvd(keyword, max_results=max_results, lookback_months=24)
        if not results:
            return f"No vulnerabilities found for '{keyword}'."
        kev_list = fetch_kev_catalog()
        enriched = []
        for item in results[:max_results]:
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

def agent_query(user_message: str, conversation_history: List[Dict], context: str = "") -> Tuple[str, List[Dict]]:
    """Process user message with tool calling."""
    if not GROQ_API_KEY:
        return "Groq API key not configured. AI Agent disabled.", conversation_history

    messages = []
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_message})

    system_prompt = {
        "role": "system",
        "content": f"""You are a cybersecurity analyst specialized in OT/ICS vulnerabilities.
You have access to tools to search NVD, get CVE details, list KEV, and get ICS-CERT advisories.
Use these tools to answer questions about the uploaded assets and their vulnerabilities.
Context about the assets (from the Excel file) may be provided below.

Asset Context:
{context}

Be concise but thorough. When asked about a specific asset, search for its vulnerabilities using the appropriate tools."""
    }
    if not messages or messages[0].get("role") != "system":
        messages.insert(0, system_prompt)

    max_iterations = 5
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
    st.title("🛡️ OT Threat Intelligence")
    st.markdown("Upload an Excel/CSV file with your OT assets, then map columns to asset fields. The AI will analyze vulnerabilities and provide a summary.")

    # File upload
    uploaded_file = st.file_uploader("Choose file", type=["xlsx", "csv"])
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
                with col3:
                    col_map["firmware"] = st.selectbox("Firmware (optional)", ["-- None --"] + cols, index=0)
                submit = st.form_submit_button("Analyze Assets")

            if submit:
                # Remove "None" selections
                col_map = {k: v for k, v in col_map.items() if v != "-- None --"}
                if "asset_name" not in col_map:
                    st.error("Asset Name is required for analysis.")
                    return

                # Analyze
                with st.spinner("Analyzing assets for vulnerabilities (this may take a few minutes)..."):
                    df_vulns = analyze_assets(df, col_map, lookback_months=24)
                    st.session_state.vuln_df = df_vulns
                    st.session_state.asset_df = df
                    st.session_state.asset_count = len(df)

                if df_vulns.empty:
                    st.warning("No vulnerabilities found. Try adjusting the lookback period or check your asset data.")
                else:
                    # Generate summary
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
    st.markdown("Ask questions about the assets, vulnerabilities, or any related threats. The agent can search NVD, get CVE details, list KEV, and fetch ICS advisories.")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Provide context from assets (if any) to the agent
    context_str = ""
    if "asset_df" in st.session_state:
        # Show a summary of assets, not full dataframe
        context_str = f"Uploaded assets ({st.session_state.asset_count} rows):\n" + st.session_state.asset_df.head(20).to_string()

    if prompt := st.chat_input("Ask a question..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                answer, new_history = agent_query(prompt, st.session_state.messages, context_str)
                st.markdown(answer)
                # Update conversation history
                st.session_state.messages = new_history

if __name__ == "__main__":
    main()
