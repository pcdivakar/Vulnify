import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

# Email settings (for sending alerts)
try:
    SMTP_SERVER = st.secrets["SMTP_SERVER"]
    SMTP_PORT = int(st.secrets["SMTP_PORT"])
    SMTP_USER = st.secrets["SMTP_USER"]
    SMTP_PASSWORD = st.secrets["SMTP_PASSWORD"]
except:
    SMTP_SERVER = None

# ---------- Custom CSS ----------
st.markdown("""
<style>
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
    .graph-container {
        background: white;
        border-radius: 12px;
        padding: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        border: 1px solid #e5e7eb;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Database Setup ----------
def init_db():
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (email TEXT PRIMARY KEY,
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
    c.execute('''CREATE TABLE IF NOT EXISTS asset_metadata
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  asset_id INTEGER,
                  metadata TEXT,
                  FOREIGN KEY(asset_id) REFERENCES assets(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT,
                  asset_id INTEGER,
                  cve_id TEXT,
                  sent_at TIMESTAMP,
                  status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS connections
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT,
                  source_asset_id INTEGER,
                  target_asset_id INTEGER,
                  relationship_type TEXT,
                  created_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS asset_types
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT,
                  type_name TEXT,
                  is_default INTEGER,
                  created_at TIMESTAMP)''')
    conn.commit()
    # Pre‑populate default asset types
    default_types = ["PLC", "RTU", "HMI", "SCADA", "Gateway", "IED", "VFD", "UPS", "Historian", "Engineering Workstation"]
    for dt in default_types:
        c.execute("SELECT id FROM asset_types WHERE email IS NULL AND type_name=? AND is_default=1", (dt,))
        if not c.fetchone():
            c.execute("INSERT INTO asset_types (email, type_name, is_default, created_at) VALUES (NULL, ?, 1, ?)",
                      (dt, datetime.now()))
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

def safe_float(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return 0.0

def ensure_user(email):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE email=?", (email,))
    if not c.fetchone():
        c.execute("INSERT INTO users (email, name, created_at, last_alert_check) VALUES (?, ?, ?, ?)",
                  (email, "", datetime.now(), None))
        conn.commit()
    conn.close()

# ---------- Asset Type Management ----------
def get_asset_types(email):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT type_name FROM asset_types WHERE email IS NULL AND is_default=1 ORDER BY type_name")
    defaults = [row[0] for row in c.fetchall()]
    c.execute("SELECT type_name FROM asset_types WHERE email=? AND is_default=0 ORDER BY type_name", (email,))
    customs = [row[0] for row in c.fetchall()]
    conn.close()
    return defaults + customs

def add_asset_type(email, type_name):
    if not type_name.strip():
        return False
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id FROM asset_types WHERE (email IS NULL OR email=?) AND type_name=?", (email, type_name))
    if c.fetchone():
        conn.close()
        return False
    c.execute("INSERT INTO asset_types (email, type_name, is_default, created_at) VALUES (?, ?, 0, ?)",
              (email, type_name, datetime.now()))
    conn.commit()
    conn.close()
    return True

def delete_asset_type(email, type_name):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("DELETE FROM asset_types WHERE email=? AND type_name=? AND is_default=0", (email, type_name))
    conn.commit()
    conn.close()

# ---------- Asset Management ----------
def asset_exists(email, asset_name):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id FROM assets WHERE email=? AND asset_name=?", (email, asset_name))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def add_asset(email, asset_name, asset_type, location, metadata=None):
    if asset_exists(email, asset_name):
        return False, None
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("INSERT INTO assets (email, asset_name, asset_type, location, created_at) VALUES (?, ?, ?, ?, ?)",
              (email, asset_name, asset_type, location, datetime.now()))
    asset_id = c.lastrowid
    if metadata:
        c.execute("INSERT INTO asset_metadata (asset_id, metadata) VALUES (?, ?)",
                  (asset_id, json.dumps(metadata)))
    conn.commit()
    conn.close()
    return True, asset_id

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
    c.execute("DELETE FROM connections WHERE source_asset_id=? OR target_asset_id=?", (asset_id, asset_id))
    c.execute("DELETE FROM asset_metadata WHERE asset_id=?", (asset_id,))
    conn.commit()
    conn.close()

def delete_all_assets(email):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("DELETE FROM assets WHERE email=?", (email,))
    c.execute("DELETE FROM connections WHERE email=?", (email,))
    c.execute("DELETE FROM asset_metadata WHERE asset_id IN (SELECT id FROM assets WHERE email=?)", (email,))
    conn.commit()
    conn.close()

def get_asset_by_id(asset_id):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id, asset_name, asset_type, location FROM assets WHERE id=?", (asset_id,))
    row = c.fetchone()
    conn.close()
    return row

def get_asset_id_by_name(email, asset_name):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id FROM assets WHERE email=? AND asset_name=?", (email, asset_name))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# ---------- Connection Management ----------
def add_connection(email, source_id, target_id, rel_type):
    if source_id == target_id:
        return False
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id FROM connections WHERE email=? AND source_asset_id=? AND target_asset_id=?",
              (email, source_id, target_id))
    if c.fetchone():
        conn.close()
        return False
    c.execute("INSERT INTO connections (email, source_asset_id, target_asset_id, relationship_type, created_at) VALUES (?, ?, ?, ?, ?)",
              (email, source_id, target_id, rel_type, datetime.now()))
    conn.commit()
    conn.close()
    return True

def get_connections(email):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT id, source_asset_id, target_asset_id, relationship_type FROM connections WHERE email=?", (email,))
    rows = c.fetchall()
    conn.close()
    return rows

def delete_connection(conn_id):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("DELETE FROM connections WHERE id=?", (conn_id,))
    conn.commit()
    conn.close()

def delete_all_connections(email):
    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("DELETE FROM connections WHERE email=?", (email,))
    conn.commit()
    conn.close()

def build_network_graph(email):
    G = nx.DiGraph()
    assets = get_user_assets(email)
    for asset_id, name, typ, loc, _ in assets:
        G.add_node(asset_id, name=name, type=typ, location=loc)
    connections = get_connections(email)
    for conn_id, src, tgt, rel_type in connections:
        G.add_edge(src, tgt, relationship=rel_type)
    return G

# ---------- Vulnerability Analysis Functions (with lookback) ----------
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
def search_nvd(keyword: str, lookback_months: int, max_results: int = 50) -> List[Dict]:
    """Search NVD with keyword, only looking back `lookback_months` months."""
    max_results = int(max_results)
    results = []
    start_index = 0

    start_date = datetime.now() - timedelta(days=lookback_months * 30)
    end_date = datetime.now()

    # Enhance OT context
    ot_terms = ["ics", "scada", "plc", "rtu", "hmi", "modbus", "opc", "profibus", "fieldbus"]
    if any(term in keyword.lower() for term in ot_terms):
        keyword += " ics"

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
def check_new_alerts(user_email, lookback_months):
    assets = get_user_assets(user_email)
    if not assets:
        return False, "No assets to check."

    conn = sqlite3.connect('ot_platform.db')
    c = conn.cursor()
    c.execute("SELECT last_alert_check FROM users WHERE email=?", (user_email,))
    row = c.fetchone()
    last_check = row[0] if row else None

    kev_list = fetch_kev_catalog()
    new_alerts = []
    for asset_id, asset_name, asset_type, location, _ in assets:
        cve_list = search_nvd(asset_name, lookback_months, max_results=20)
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

# ---------- LLM Agent ----------
def simple_llm_query(prompt: str) -> str:
    if not GROQ_API_KEY:
        return "Groq API key not configured."
    client = groq.Groq(api_key=GROQ_API_KEY)
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"

def agent_query(user_message: str, conversation_history: List[Dict], network_context: str = "") -> Tuple[str, List[Dict]]:
    if not GROQ_API_KEY:
        return "Groq API key not configured. AI Agent disabled.", conversation_history

    messages = []
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_message})

    system_prompt = {
        "role": "system",
        "content": f"""You are an OT/ICS cybersecurity analyst. You have access to tools to search for CVEs, get details, list KEV, and get ICS advisories.
If the user asks about a specific asset, use the network architecture information provided below to understand upstream/downstream dependencies and predict impact propagation.

Network Architecture:
{network_context}

When using tools, ensure numeric parameters are integers (no quotes). Consider OT/ICS implications and network dependencies in your answers."""
    }
    if not messages or messages[0].get("role") != "system":
        messages.insert(0, system_prompt)

    tools = [
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

    max_iterations = 10
    iteration = 0

    while iteration < max_iterations:
        client = groq.Groq(api_key=GROQ_API_KEY)
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                tools=tools,
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

def execute_tool(tool_name: str, arguments: Dict) -> str:
    # This function needs access to the current lookback. We'll pass it via session_state.
    # However, to avoid a circular dependency, we'll read from st.session_state inside the function.
    lookback_months = st.session_state.get("lookback_months", 24)
    if tool_name == "search_vulnerabilities":
        keyword = arguments["keyword"]
        max_results = arguments.get("max_results", 10)
        try:
            max_results = int(max_results)
        except:
            max_results = 10
        basic_results = search_nvd(keyword, lookback_months, max_results=max_results)
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

# ---------- Dashboard Functions (with lookback) ----------
def analyze_assets(user_email, lookback_months):
    assets = get_user_assets(user_email)
    if not assets:
        return pd.DataFrame(), {}

    kev_list = fetch_kev_catalog()
    all_vulns = []
    for asset_id, asset_name, asset_type, location, _ in assets:
        cve_list = search_nvd(asset_name, lookback_months, max_results=20)
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

def get_asset_epss_summary(user_email, df):
    if df.empty:
        return pd.DataFrame()
    agg = df.groupby("asset").agg(
        max_epss=("epss", "max"),
        avg_epss=("epss", "mean"),
        high_risk_count=("epss", lambda x: (x > 0.5).sum())
    ).reset_index()
    agg["risk_level"] = agg["max_epss"].apply(
        lambda x: "Very High" if x > 0.8 else ("High" if x > 0.5 else ("Medium" if x > 0.2 else "Low"))
    )
    return agg.sort_values("max_epss", ascending=False)

def get_latest_cves_for_assets(user_email, lookback_months, limit=5):
    assets = get_user_assets(user_email)
    if not assets:
        return []
    kev_list = fetch_kev_catalog()
    all_cves = []
    for asset_id, asset_name, asset_type, location, _ in assets:
        cve_list = search_nvd(asset_name, lookback_months, max_results=5)
        for item in cve_list:
            enriched = enrich_cve(item["cve"], kev_list)
            if enriched:
                enriched["asset"] = asset_name
                try:
                    enriched["cvss_score"] = float(enriched["cvss_score"])
                except:
                    enriched["cvss_score"] = 0.0
                all_cves.append(enriched)
    all_cves.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    return all_cves[:limit]

# ---------- Network Graph Visualization ----------
def plot_network_graph(email, type_colors, seed=None):
    G = build_network_graph(email)
    if G.number_of_nodes() == 0:
        return None

    if seed is None:
        seed = 42
    pos = nx.spring_layout(G, k=3, iterations=80, seed=seed)

    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    node_sizes = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_data = G.nodes[node]
        asset_type = node_data['type']
        color = type_colors.get(asset_type, "#aaaaaa")
        node_colors.append(color)
        node_sizes.append(40)
        node_text.append(
            f"<b>{node_data['name']}</b><br>Type: {asset_type}<br>Location: {node_data['location']}"
        )

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        textposition="top center",
        hoverinfo='text',
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color='white')
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title=None,
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20, l=20, r=20, t=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='white',
        paper_bgcolor='white'
    )
    return fig

# ---------- Main App ----------
def main():
    # Sidebar: Email input and lookback
    with st.sidebar:
        st.markdown("### 📧 Your Email")
        email = st.text_input("Email for alerts", value=st.session_state.get("user_email", ""), key="user_email_input")
        if st.button("Set Email"):
            if email and "@" in email:
                st.session_state.user_email = email
                ensure_user(email)
                st.success(f"Email set to {email}")
                st.rerun()
            else:
                st.error("Please enter a valid email address.")

        if "user_email" in st.session_state:
            st.markdown(f"**Active email:** {st.session_state.user_email}")
            if st.button("Change Email"):
                del st.session_state.user_email
                st.rerun()
        else:
            st.info("Enter your email to start.")

        st.markdown("---")
        st.markdown("### 🔍 Vulnerability Lookback")
        lookback_months = st.slider("Months of data to analyze", min_value=1, max_value=60, value=24, step=1,
                                    help="How many months back to search for CVEs")
        if "lookback_months" not in st.session_state or st.session_state.lookback_months != lookback_months:
            st.session_state.lookback_months = lookback_months
            # Clear cache to force refresh
            st.cache_data.clear()
            st.rerun()

    # If no email set, show prompt and exit
    if "user_email" not in st.session_state or not st.session_state.user_email:
        st.markdown('<div class="main-header">🏭 OT Vulnerability Intelligence Platform</div>', unsafe_allow_html=True)
        st.info("👋 Please enter your email in the sidebar to begin.")
        return

    user_email = st.session_state.user_email
    lookback = st.session_state.lookback_months

    # Sidebar navigation (only shown when email is set)
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 🏭 Navigation")
        page = st.radio("", ["Dashboard", "Asset Manager", "Network Architecture", "AI Agent"])

    if page == "Dashboard":
        st.markdown('<div class="main-header">📊 OT Vulnerability Dashboard</div>', unsafe_allow_html=True)

        # Dashboard action buttons
        col_actions = st.columns([1,1,1])
        with col_actions[0]:
            if st.button("🔄 Refresh Data", help="Re‑fetch vulnerabilities for all assets"):
                st.cache_data.clear()
                st.rerun()
        with col_actions[1]:
            if st.button("📧 Check Alerts", help="Manually check for new vulnerabilities and send email"):
                with st.spinner("Checking..."):
                    sent, msg = check_new_alerts(user_email, lookback)
                    st.success(msg)
        with col_actions[2]:
            if st.button("🗑️ Clear All Assets", help="Delete all your assets and connections"):
                if st.checkbox("Confirm delete all assets?"):
                    delete_all_assets(user_email)
                    st.success("All assets and connections deleted.")
                    st.rerun()

        # On first load of the session, check for new alerts (only once)
        if "alert_checked" not in st.session_state:
            with st.spinner("Checking for new vulnerabilities..."):
                _, msg = check_new_alerts(user_email, lookback)
                st.info(msg)
                st.session_state.alert_checked = True

        with st.spinner("Analyzing your assets..."):
            df, stats = analyze_assets(user_email, lookback)

        assets = get_user_assets(user_email)
        if not assets:
            st.warning("No assets found. Please add assets in the Asset Manager.")
            return

        if df.empty:
            st.info(f"✅ Your assets have been imported. No CVEs found in the last {lookback} months.")
            st.subheader("Your Assets")
            asset_list = [a[1] for a in assets]
            st.write("Assets:", ", ".join(asset_list))
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

        # EPSS Proactive Analysis
        asset_epss = get_asset_epss_summary(user_email, df)
        if not asset_epss.empty:
            st.subheader("🚨 Assets with Highest Exploitation Probability (EPSS)")
            col1, col2 = st.columns([2, 1])
            with col1:
                fig_epss = px.bar(asset_epss.head(10), x="asset", y="max_epss",
                                  color="risk_level",
                                  color_discrete_map={"Very High": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#10b981"},
                                  title="Top 10 Assets by Max EPSS Score",
                                  labels={"max_epss": "EPSS Score (0-1)", "asset": "Asset"})
                st.plotly_chart(fig_epss, use_container_width=True)
            with col2:
                st.markdown("**Why these assets are high risk:**")
                if st.button("Generate AI Explanation", key="epss_btn"):
                    top_assets = asset_epss.head(5)["asset"].tolist()
                    vuln_data = df[df["asset"].isin(top_assets)][["asset", "cve", "epss", "description"]].head(20)
                    prompt = f"""
You are an OT cybersecurity analyst. Explain why the following assets are at high risk of exploitation in the next 30 days based on their EPSS scores. Provide a concise, actionable summary for the security team.

Assets and their top vulnerabilities (EPSS > 0.5):
{vuln_data.to_string()}
"""
                    with st.spinner("Generating explanation..."):
                        explanation = simple_llm_query(prompt)
                        st.write(explanation)

        # Latest relevant CVEs
        st.subheader("Latest Relevant CVEs for Your Assets")
        latest_cves = get_latest_cves_for_assets(user_email, lookback, limit=10)
        if latest_cves:
            latest_df = pd.DataFrame(latest_cves)
            latest_df["cvss_score"] = pd.to_numeric(latest_df["cvss_score"], errors="coerce")
            latest_df["epss"] = pd.to_numeric(latest_df["epss"], errors="coerce")
            latest_df = latest_df[["asset", "cve", "cvss_score", "epss", "kev", "description"]]
            latest_df["cvss_score"] = latest_df["cvss_score"].round(1)
            latest_df["epss"] = latest_df["epss"].round(4)
            latest_df["kev"] = latest_df["kev"].apply(lambda x: "Yes" if x else "No")
            st.dataframe(latest_df, use_container_width=True)
        else:
            st.info(f"No CVEs found for your assets in the last {lookback} months.")

        # Detailed table
        st.subheader("Detailed Vulnerability List")
        display_df = df[["asset", "cve", "cvss_score", "epss", "risk", "description"]].copy()
        display_df["cvss_score"] = pd.to_numeric(display_df["cvss_score"], errors="coerce")
        display_df["epss"] = pd.to_numeric(display_df["epss"], errors="coerce")
        display_df["cvss_score"] = display_df["cvss_score"].round(1)
        display_df["epss"] = display_df["epss"].round(4)
        st.dataframe(display_df, use_container_width=True)

    elif page == "Asset Manager":
        # [Asset Manager code – same as before, but with lookback passed to search functions if needed]
        # For brevity, the Asset Manager code remains unchanged from the previous version.
        # (We keep it exactly as in the earlier version, but we don't need to repeat it here.)
        pass

    elif page == "Network Architecture":
        # [Network Architecture code – same as before]
        pass

    elif page == "AI Agent":
        # [AI Agent code – same as before]
        pass

# We need to include the full Asset Manager, Network Architecture and AI Agent code again, but to keep the answer manageable,
# I'll skip re‑writing them here. They should be the same as in the previous final version.
# For a complete working app, combine the above with the full code from the previous answer (the one that included all tabs).
