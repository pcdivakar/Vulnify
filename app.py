import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime, timedelta
import time
import json
import uuid
import groq
import sqlite3
import smtplib
import random
import string
import hashlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import io
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

# Email settings
try:
    SMTP_SERVER = st.secrets["SMTP_SERVER"]
    SMTP_PORT = int(st.secrets["SMTP_PORT"])
    SMTP_USER = st.secrets["SMTP_USER"]
    SMTP_PASSWORD = st.secrets["SMTP_PASSWORD"]
except:
    SMTP_SERVER = None

# ---------- Custom CSS for Corporate Light Theme ----------
st.markdown("""
<style>
    /* Global styles */
    .stApp {
        background-color: #f5f7fb;
    }
    .main-header {
        font-size: 2rem;
        font-weight: 600;
        color: #1e3a8a;
        margin-bottom: 1rem;
        border-left: 4px solid #3b82f6;
        padding-left: 1rem;
    }
    .metric-card {
        background: white;
        border-radius: 12px;
        padding: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        border: 1px solid #e5e7eb;
        transition: all 0.2s;
    }
    .metric-card:hover {
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    .stat-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #111827;
    }
    .stat-label {
        font-size: 0.85rem;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .risk-critical {
        color: #dc2626;
        font-weight: 600;
    }
    .risk-high {
        color: #f97316;
        font-weight: 600;
    }
    .risk-medium {
        color: #eab308;
        font-weight: 600;
    }
    .risk-low {
        color: #10b981;
        font-weight: 600;
    }
    .stButton > button {
        background-color: #3b82f6;
        color: white;
        border-radius: 6px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: 500;
    }
    .stButton > button:hover {
        background-color: #2563eb;
    }
    .stTextInput > div > input, .stTextArea > div > textarea {
        border-radius: 6px;
        border: 1px solid #e5e7eb;
    }
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid #e5e7eb;
    }
    .css-1d391kg {
        background-color: white;
        border-radius: 12px;
        padding: 1rem;
        margin-bottom: 1rem;
        border: 1px solid #e5e7eb;
    }
    hr {
        margin: 1rem 0;
        border-color: #e5e7eb;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Database Setup ----------
def init_db():
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (email TEXT PRIMARY KEY,
                  password TEXT,
                  name TEXT,
                  created_at TIMESTAMP,
                  last_alert_check TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS assets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT,
                  asset_name TEXT,
                  asset_type TEXT,
                  location TEXT,
                  created_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT,
                  asset_id INTEGER,
                  cve_id TEXT,
                  sent_at TIMESTAMP,
                  status TEXT)''')
    conn.commit()
    conn.close()

init_db()

# ---------- Helper Functions ----------
def send_email(to_email, subject, body):
    if not SMTP_SERVER:
        return False
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"Email error: {e}")
        return False

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def safe_float(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return 0.0

# ---------- Authentication ----------
def login_page():
    st.markdown('<div class="main-header">🏭 OT Vulnerability Intelligence Platform</div>', unsafe_allow_html=True)
    st.subheader("Secure Access")
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if not email or not password:
                st.error("Please fill all fields.")
            else:
                conn = sqlite3.connect('ot_platform.db')
                c = conn.cursor()
                c.execute("SELECT email, password FROM users WHERE email=?", (email,))
                row = c.fetchone()
                conn.close()
                if row and row[1] == hash_password(password):
                    st.session_state.logged_in = True
                    st.session_state.user_email = email
                    st.rerun()
                else:
                    st.error("Invalid email or password.")
    
    with tab2:
        name = st.text_input("Full Name", key="reg_name")
        email = st.text_input("Email", key="reg_email")
        password = st.text_input("Password", type="password", key="reg_password")
        confirm = st.text_input("Confirm Password", type="password")
        if st.button("Register"):
            if not name or not email or not password:
                st.error("Please fill all fields.")
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                conn = sqlite3.connect('ot_platform.db')
                c = conn.cursor()
                c.execute("SELECT email FROM users WHERE email=?", (email,))
                if c.fetchone():
                    st.error("Email already registered.")
                else:
                    c.execute("INSERT INTO users (email, password, name, created_at, last_alert_check) VALUES (?, ?, ?, ?, ?)",
                              (email, hash_password(password), name, datetime.now(), None))
                    conn.commit()
                    st.success("Registration successful! You can now login.")
                conn.close()

def logout():
    st.session_state.logged_in = False
    st.session_state.user_email = None
    st.rerun()

# ---------- Asset Management ----------
def add_asset(email, asset_name, asset_type, location):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("INSERT INTO assets (email, asset_name, asset_type, location, created_at) VALUES (?, ?, ?, ?, ?)",
              (email, asset_name, asset_type, location, datetime.now()))
    conn.commit()
    conn.close()

def get_user_assets(email):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id, asset_name, asset_type, location, created_at FROM assets WHERE email=? ORDER BY created_at DESC", (email,))
    rows = c.fetchall()
    conn.close()
    return rows

def delete_asset(asset_id):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    conn.commit()
    conn.close()

# ---------- Vulnerability Analysis Functions ----------
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

@st.cache_data(ttl=86400, show_spinner=False)
def fetch_ics_advisories() -> List[Dict]:
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
    max_results = int(max_results)
    results = []
    start_index = 0
    # Enhance OT context
    ot_terms = ["ics", "scada", "plc", "rtu", "hmi", "modbus", "opc", "profibus", "fieldbus"]
    if any(term in keyword.lower() for term in ot_terms):
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
    try:
        cvss = float(nvd["cvss_score"])
    except (ValueError, TypeError):
        cvss = "N/A"
    return {
        "cve": cve_id,
        "cvss_score": cvss,
        "epss": epss,
        "kev": in_kev,
        "past_likelihood": past_likelihood,
        "description": nvd["description"]
    }

# ---------- Alert Check ----------
def check_new_alerts(user_email):
    assets = get_user_assets(user_email)
    if not assets:
        return False, "No assets to check."

    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT last_alert_check FROM users WHERE email=?", (user_email,))
    row = c.fetchone()
    last_check = row[0] if row else None
    last_check_dt = datetime.fromisoformat(last_check) if last_check else None

    kev_list = fetch_kev_catalog()
    new_alerts = []
    for asset_id, asset_name, asset_type, location, _ in assets:
        cve_list = search_nvd(asset_name, max_results=20)
        for item in cve_list:
            cve_id = item["cve"]
            c.execute("SELECT id FROM alerts WHERE email=? AND asset_id=? AND cve_id=?", (user_email, asset_id, cve_id))
            if not c.fetchone():
                enriched = enrich_cve(cve_id, kev_list)
                if enriched:
                    new_alerts.append({
                        "asset": asset_name,
                        "cve": cve_id,
                        "cvss": enriched["cvss_score"],
                        "kev": enriched["kev"],
                        "description": enriched["description"][:200]
                    })
                    c.execute("INSERT INTO alerts (email, asset_id, cve_id, sent_at, status) VALUES (?, ?, ?, ?, ?)",
                              (user_email, asset_id, cve_id, datetime.now(), "sent"))
        time.sleep(0.5)

    if new_alerts:
        subject = f"New OT Vulnerability Alerts for Your Assets"
        body = f"Dear user,\n\nWe found {len(new_alerts)} new vulnerabilities affecting your assets:\n\n"
        for alert in new_alerts:
            body += f"- {alert['asset']}: {alert['cve']} (CVSS: {alert['cvss']}, KEV: {alert['kev']})\n  {alert['description']}\n\n"
        body += "\nPlease log in to your dashboard for more details.\n\nOT Vulnerability Intelligence Platform"
        send_email(user_email, subject, body)
        c.execute("UPDATE users SET last_alert_check=? WHERE email=?", (datetime.now().isoformat(), user_email))
        conn.commit()
        conn.close()
        return True, f"Found {len(new_alerts)} new vulnerabilities. Email alert sent."
    else:
        c.execute("UPDATE users SET last_alert_check=? WHERE email=?", (datetime.now().isoformat(), user_email))
        conn.commit()
        conn.close()
        return False, "No new vulnerabilities found."

# ---------- LLM Agent Tools ----------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_vulnerabilities",
            "description": "Search for vulnerabilities by keyword, with optional OT focus.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "Search term"},
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
            "description": "Get recent ICS-CERT advisories.",
            "parameters": {"type": "object", "properties": {}}
        }
    }
]

def execute_tool(tool_name: str, arguments: Dict) -> str:
    if tool_name == "search_vulnerabilities":
        keyword = arguments["keyword"]
        max_results = arguments.get("max_results", 10)
        # Convert to int in case LLM sends string
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
    if not GROQ_API_KEY:
        return "Groq API key not configured. AI Agent disabled.", conversation_history

    messages = []
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_message})

    system_prompt = {
        "role": "system",
        "content": "You are an OT/ICS cybersecurity analyst. Use tools to gather data. When using tools, ensure numeric parameters are integers (no quotes). Consider OT/ICS implications in your answers."
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

# ---------- Dashboard Functions ----------
def analyze_assets(user_email):
    assets = get_user_assets(user_email)
    if not assets:
        return pd.DataFrame(), {}

    kev_list = fetch_kev_catalog()
    all_vulns = []
    for asset_id, asset_name, asset_type, location, _ in assets:
        cve_list = search_nvd(asset_name, max_results=20)
        for item in cve_list:
            enriched = enrich_cve(item["cve"], kev_list)
            if enriched:
                enriched["asset"] = asset_name
                enriched["asset_type"] = asset_type
                enriched["location"] = location
                all_vulns.append(enriched)

    df = pd.DataFrame(all_vulns)
    if df.empty:
        return df, {}

    df["cvss_score"] = df["cvss_score"].apply(safe_float)
    df["epss"] = df["epss"].fillna(0).apply(safe_float)

    df["risk"] = df.apply(lambda x: "Critical" if x["kev"] else ("High" if x["cvss_score"] > 7 else ("Medium" if x["cvss_score"] > 4 else "Low")), axis=1)

    stats = {
        "total_vulns": len(df),
        "critical_count": len(df[df["risk"] == "Critical"]),
        "high_count": len(df[df["risk"] == "High"]),
        "medium_count": len(df[df["risk"] == "Medium"]),
        "low_count": len(df[df["risk"] == "Low"]),
        "avg_cvss": df["cvss_score"].mean(),
        "max_cvss": df["cvss_score"].max(),
        "assets_affected": df["asset"].nunique()
    }
    return df, stats

# ---------- Main App ----------
def main():
    if "logged_in" not in st.session_state or not st.session_state.logged_in:
        login_page()
        return

    user_email = st.session_state.user_email

    # Sidebar
    with st.sidebar:
        st.markdown("### 🏭 Navigation")
        page = st.radio("", ["Dashboard", "Asset Manager", "AI Agent"])
        st.markdown("---")
        st.markdown(f"**Logged in as**  \n{user_email}")
        if st.button("Logout"):
            logout()

    if page == "Dashboard":
        st.markdown('<div class="main-header">📊 OT Vulnerability Dashboard</div>', unsafe_allow_html=True)

        # On login, automatically check for new alerts (once per session)
        if "alert_checked" not in st.session_state:
            with st.spinner("Checking for new vulnerabilities..."):
                _, msg = check_new_alerts(user_email)
                st.info(msg)
                st.session_state.alert_checked = True

        # Manual check button
        col1, col2 = st.columns([1, 5])
        with col1:
            if st.button("🔄 Check for New Alerts"):
                with st.spinner("Checking..."):
                    sent, msg = check_new_alerts(user_email)
                    st.success(msg)

        with st.spinner("Analyzing your assets..."):
            df, stats = analyze_assets(user_email)

        if df.empty:
            st.warning("No assets found. Please add assets in the Asset Manager.")
            return

        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown('<div class="metric-card"><div class="stat-label">Total Vulnerabilities</div><div class="stat-value">{}</div></div>'.format(stats["total_vulns"]), unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="metric-card"><div class="stat-label">Critical/High</div><div class="stat-value">{}</div></div>'.format(stats["critical_count"] + stats["high_count"]), unsafe_allow_html=True)
        with col3:
            st.markdown('<div class="metric-card"><div class="stat-label">Average CVSS</div><div class="stat-value">{:.1f}</div></div>'.format(stats["avg_cvss"]), unsafe_allow_html=True)
        with col4:
            st.markdown('<div class="metric-card"><div class="stat-label">Assets Affected</div><div class="stat-value">{}</div></div>'.format(stats["assets_affected"]), unsafe_allow_html=True)

        # Severity distribution chart
        st.subheader("Risk Severity Distribution")
        severity_data = pd.DataFrame({
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [stats["critical_count"], stats["high_count"], stats["medium_count"], stats["low_count"]]
        })
        fig = px.bar(severity_data, x="Severity", y="Count", color="Severity",
                     color_discrete_map={"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#10b981"},
                     title="")
        st.plotly_chart(fig, use_container_width=True)

        # CVSS vs EPSS scatter plot
        st.subheader("CVSS vs EPSS Risk Matrix")
        fig2 = px.scatter(df, x="cvss_score", y="epss", hover_name="cve", color="risk",
                          color_discrete_map={"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "green"},
                          title="")
        st.plotly_chart(fig2, use_container_width=True)

        # Top assets by vulnerability count
        st.subheader("Top Assets by Vulnerability Count")
        asset_counts = df.groupby("asset").size().reset_index(name="count")
        fig3 = px.bar(asset_counts.sort_values("count", ascending=False).head(10),
                      x="asset", y="count", title="")
        st.plotly_chart(fig3, use_container_width=True)

        # Detailed table
        st.subheader("Detailed Vulnerability List")
        display_df = df[["asset", "cve", "cvss_score", "epss", "risk", "description"]].copy()
        display_df["cvss_score"] = display_df["cvss_score"].round(1)
        display_df["epss"] = display_df["epss"].round(4)
        st.dataframe(display_df, use_container_width=True)

    elif page == "Asset Manager":
        st.markdown('<div class="main-header">📦 Asset Manager</div>', unsafe_allow_html=True)
        st.markdown("Manage your OT assets – add manually or import from Excel/CSV.")

        with st.expander("➕ Add Asset Manually"):
            col1, col2, col3 = st.columns(3)
            with col1:
                asset_name = st.text_input("Asset Name")
            with col2:
                asset_type = st.selectbox("Asset Type", ["PLC", "RTU", "HMI", "SCADA", "Gateway", "Other"])
            with col3:
                location = st.text_input("Location (optional)")
            if st.button("Add Asset"):
                if asset_name:
                    add_asset(user_email, asset_name, asset_type, location)
                    st.success(f"Added {asset_name}")
                    st.rerun()
                else:
                    st.warning("Please enter an asset name.")

        with st.expander("📎 Import from Excel/CSV"):
            uploaded_file = st.file_uploader("Choose file", type=["xlsx", "csv"])
            if uploaded_file:
                try:
                    if uploaded_file.name.endswith('.csv'):
                        df = pd.read_csv(uploaded_file)
                    else:
                        df = pd.read_excel(uploaded_file)
                    for idx, row in df.iterrows():
                        name = str(row.iloc[0]).strip()
                        if name and name != "nan":
                            asset_type = str(row.iloc[1]) if len(row) > 1 else "Other"
                            location = str(row.iloc[2]) if len(row) > 2 else ""
                            add_asset(user_email, name, asset_type, location)
                    st.success(f"Imported {len(df)} assets.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error reading file: {e}")

        st.subheader("Your Assets")
        assets = get_user_assets(user_email)
        if not assets:
            st.info("No assets yet. Add some using the forms above.")
        else:
            for asset_id, asset_name, asset_type, location, created_at in assets:
                col1, col2, col3, col4, col5 = st.columns([2, 1, 1, 2, 1])
                col1.write(f"**{asset_name}**")
                col2.write(asset_type)
                col3.write(location if location else "—")
                col4.write(created_at[:10])
                if col5.button("Delete", key=f"del_{asset_id}"):
                    delete_asset(asset_id)
                    st.rerun()

    elif page == "AI Agent":
        st.markdown('<div class="main-header">🤖 OT Vulnerability Agent</div>', unsafe_allow_html=True)
        st.markdown("Ask any question about OT/ICS vulnerabilities. The agent can search NVD, fetch KEV, and get ICS advisories.")

        if not GROQ_API_KEY:
            st.error("Groq API key not configured. AI Agent disabled.")
        else:
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
