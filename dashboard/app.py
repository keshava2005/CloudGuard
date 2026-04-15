import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import boto3
import streamlit as st

from scanner.iam_scanner import check_users_without_mfa
from scanner.s3_scanner import check_public_buckets
from scanner.ec2_scanner import check_open_security_groups
from scanner.cloudtrail_scanner import check_cloudtrail_status

from engine.risk_engine import calculate_risk
from engine.pdf_report import generate_pdf
from engine.email_sender import send_email


# ------------------ PAGE CONFIG ------------------
st.set_page_config(page_title="CloudGuard", layout="wide", page_icon="🛡️")

# ------------------ CUSTOM CSS ------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@300;400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; }

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

/* ── APP BACKGROUND ── */
.stApp {
    background: #060d1a !important;
    min-height: 100vh;
}

.stApp::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
        linear-gradient(rgba(0,212,255,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,.03) 1px, transparent 1px);
    background-size: 50px 50px;
    pointer-events: none;
    z-index: 0;
}

.stApp::after {
    content: '';
    position: fixed;
    top: -250px; right: -150px;
    width: 700px; height: 700px;
    background: radial-gradient(circle, rgba(16,185,129,.07) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
    animation: floatOrb 18s ease-in-out infinite alternate;
}
@keyframes floatOrb {
    0%   { transform: translate(0,0) scale(1); }
    100% { transform: translate(-80px,100px) scale(1.1); }
}

/* ── LAYOUT ── */
.block-container {
    padding: 48px 64px 80px !important;
    max-width: 1240px !important;
    margin: 0 auto !important;
    position: relative;
    z-index: 1;
}

/* ── SIDEBAR ── */
[data-testid="stSidebar"] {
    background: #050c18 !important;
    border-right: 1px solid rgba(16,185,129,.12) !important;
}
[data-testid="stSidebar"] > div:first-child {
    padding: 32px 24px !important;
}
.sidebar-logo {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 28px;
    padding-bottom: 20px;
    border-bottom: 1px solid rgba(16,185,129,.12);
}
.sidebar-logo-icon {
    font-size: 26px;
}
.sidebar-logo-text {
    font-family: 'Inter', sans-serif;
    font-size: 18px;
    font-weight: 800;
    color: #f0f6ff;
    letter-spacing: -.5px;
}
.sidebar-logo-text span { color: #10b981; }
.sidebar-section {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #3d5a7a;
    margin-bottom: 16px;
    margin-top: 8px;
}
.conn-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: 10px;
    margin-bottom: 20px;
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 600;
}
.conn-badge.connected {
    background: rgba(16,185,129,.1);
    border: 1px solid rgba(16,185,129,.25);
    color: #10b981;
}
.conn-badge.disconnected {
    background: rgba(239,68,68,.07);
    border: 1px solid rgba(239,68,68,.2);
    color: #ef4444;
}
.conn-badge.demo {
    background: rgba(245,158,11,.07);
    border: 1px solid rgba(245,158,11,.2);
    color: #f59e0b;
}
.conn-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}
.conn-dot.green  { background: #10b981; box-shadow: 0 0 6px rgba(16,185,129,.8); animation: pulse 2.5s infinite; }
.conn-dot.red    { background: #ef4444; box-shadow: 0 0 6px rgba(239,68,68,.8); }
.conn-dot.yellow { background: #f59e0b; box-shadow: 0 0 6px rgba(245,158,11,.8); }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

.account-info {
    background: rgba(255,255,255,.03);
    border: 1px solid rgba(61,90,122,.2);
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #5a7a9a;
    line-height: 1.8;
}
.account-info span { color: #10b981; font-weight: 600; }

/* ── SIDEBAR INPUTS ── */
[data-testid="stSidebar"] .stTextInput > div > div,
[data-testid="stSidebar"] .stSelectbox > div > div {
    background: rgba(255,255,255,.04) !important;
    border: 1px solid rgba(61,90,122,.4) !important;
    border-radius: 10px !important;
    color: #e2eaf4 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
}
[data-testid="stSidebar"] .stTextInput > div > div:focus-within {
    border-color: rgba(16,185,129,.5) !important;
    box-shadow: 0 0 0 3px rgba(16,185,129,.1) !important;
}
[data-testid="stSidebar"] .stTextInput label,
[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stTextArea label {
    font-family: 'Inter', sans-serif !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    color: #5a7a9a !important;
}
[data-testid="stSidebar"] .stTextArea > div > div {
    background: rgba(255,255,255,.04) !important;
    border: 1px solid rgba(61,90,122,.4) !important;
    border-radius: 10px !important;
    color: #e2eaf4 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
}
[data-testid="stSidebar"] .stButton > button {
    height: 44px !important;
    font-size: 12px !important;
    letter-spacing: 1.5px !important;
}

/* ── HEADER BADGE ── */
.cg-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(16,185,129,.08);
    border: 1px solid rgba(16,185,129,.22);
    border-radius: 100px;
    padding: 6px 16px 6px 12px;
    margin-bottom: 32px;
}
.cg-badge-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #10b981;
    box-shadow: 0 0 8px rgba(16,185,129,.8);
    animation: pulse 2.5s ease-in-out infinite;
}
.cg-badge-txt {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #10b981;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    font-weight: 500;
}

/* ── HERO ── */
.cg-hero {
    display: flex;
    align-items: center;
    gap: 24px;
    margin-bottom: 12px;
}
.cg-icon {
    width: 80px; height: 80px;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    border-radius: 22px;
    display: flex; align-items: center; justify-content: center;
    font-size: 38px;
    flex-shrink: 0;
    box-shadow: 0 0 0 1px rgba(16,185,129,.25), 0 8px 32px rgba(16,185,129,.3);
    animation: iconGlow 3.5s ease-in-out infinite;
}
@keyframes iconGlow {
    0%,100% { box-shadow: 0 0 0 1px rgba(16,185,129,.25), 0 8px 32px rgba(16,185,129,.3); }
    50%      { box-shadow: 0 0 0 1px rgba(16,185,129,.4),  0 8px 60px rgba(16,185,129,.55); }
}
.cg-title {
    font-size: 68px !important;
    font-weight: 900 !important;
    letter-spacing: -3.5px !important;
    line-height: 1 !important;
    color: #f0f6ff !important;
    margin: 0 !important;
}
.cg-title span { color: #10b981; }
.cg-subtitle {
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #3d5a7a;
    letter-spacing: 3.5px;
    text-transform: uppercase;
    margin-bottom: 40px;
    padding-left: 2px;
}
.cg-divider {
    height: 1px;
    background: linear-gradient(90deg, rgba(16,185,129,.6) 0%, rgba(16,185,129,.15) 40%, transparent 100%);
    margin-bottom: 48px;
}

/* ── SECTION LABEL ── */
.section-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: #3d5a7a;
    letter-spacing: 3.5px;
    text-transform: uppercase;
    font-weight: 500;
    margin-bottom: 18px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.section-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(61,90,122,.25);
}

/* ── MAIN INPUT ── */
.stTextInput > div > div {
    background: rgba(255,255,255,.035) !important;
    border: 1px solid rgba(61,90,122,.45) !important;
    border-radius: 14px !important;
    color: #e2eaf4 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 15px !important;
    height: 56px !important;
    padding: 0 20px !important;
    transition: border-color .25s, box-shadow .25s !important;
}
.stTextInput > div > div:focus-within {
    border-color: rgba(16,185,129,.55) !important;
    box-shadow: 0 0 0 3px rgba(16,185,129,.12) !important;
}
.stTextInput input::placeholder { color: #2d4460 !important; }
.stTextInput label {
    font-family: 'Inter', sans-serif !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    color: #5a7a9a !important;
    margin-bottom: 10px !important;
}

/* ── PRIMARY BUTTON ── */
.stButton > button {
    width: 100% !important;
    height: 56px !important;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
    color: #fff !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
    border: none !important;
    border-radius: 14px !important;
    cursor: pointer !important;
    transition: all .25s cubic-bezier(.4,0,.2,1) !important;
    box-shadow: 0 4px 24px rgba(16,185,129,.25) !important;
}
.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 40px rgba(16,185,129,.4) !important;
}
.stButton > button:active { transform: translateY(0) !important; }

/* ── ALERTS ── */
.stSuccess > div, .stWarning > div, .stError > div, .stInfo > div {
    font-family: 'Inter', sans-serif !important;
    font-size: 14px !important;
    border-radius: 14px !important;
    font-weight: 500 !important;
}

/* ── METRICS ── */
[data-testid="metric-container"] {
    background: rgba(255,255,255,.028) !important;
    border: 1px solid rgba(61,90,122,.3) !important;
    border-radius: 20px !important;
    padding: 36px 32px !important;
    position: relative;
    overflow: hidden;
    transition: border-color .3s, box-shadow .3s, transform .3s;
    backdrop-filter: blur(12px) !important;
}
[data-testid="metric-container"]::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 3px;
    background: linear-gradient(90deg, #10b981 0%, #34d399 60%, transparent 100%);
}
[data-testid="metric-container"]:hover {
    border-color: rgba(16,185,129,.35) !important;
    box-shadow: 0 8px 40px rgba(16,185,129,.1) !important;
    transform: translateY(-2px);
}
[data-testid="stMetricLabel"] > div {
    font-family: 'Inter', sans-serif !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: #5a7a9a !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 54px !important;
    font-weight: 900 !important;
    color: #10b981 !important;
    letter-spacing: -2px !important;
    line-height: 1.1 !important;
}

/* ── FINDING CARDS ── */
.finding-card {
    background: rgba(255,255,255,.025);
    border: 1px solid rgba(61,90,122,.28);
    border-radius: 18px;
    padding: 28px 28px 24px;
    margin-bottom: 16px;
    backdrop-filter: blur(10px);
    transition: border-color .25s, box-shadow .25s;
    position: relative;
    overflow: hidden;
}
.finding-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, rgba(16,185,129,.5), transparent);
}
.finding-card:hover {
    border-color: rgba(16,185,129,.25);
    box-shadow: 0 4px 30px rgba(16,185,129,.07);
}
.finding-card-title {
    font-family: 'Inter', sans-serif;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    color: #5a7a9a;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.finding-card-title .fc-icon {
    width: 28px; height: 28px;
    background: rgba(16,185,129,.12);
    border-radius: 8px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
}
.finding-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    background: rgba(255,255,255,.03);
    border: 1px solid rgba(61,90,122,.2);
    border-radius: 10px;
    margin-bottom: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #c2d4e8;
    line-height: 1.5;
}
.finding-item .fi-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #ef4444;
    margin-top: 6px;
    flex-shrink: 0;
    box-shadow: 0 0 6px rgba(239,68,68,.6);
}
.finding-ok {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: rgba(16,185,129,.06);
    border: 1px solid rgba(16,185,129,.18);
    border-radius: 10px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #10b981;
}

/* ── SECTION HEADINGS ── */
.stSubheader {
    font-family: 'Inter', sans-serif !important;
    font-size: 22px !important;
    font-weight: 800 !important;
    color: #e2eaf4 !important;
    letter-spacing: -.5px !important;
}
h3 {
    font-family: 'Inter', sans-serif !important;
    font-size: 10px !important;
    letter-spacing: 3px !important;
    text-transform: uppercase !important;
    color: #3d5a7a !important;
    font-weight: 700 !important;
    margin-bottom: 14px !important;
    padding-bottom: 12px !important;
    border-bottom: 1px solid rgba(61,90,122,.2) !important;
}
.stMarkdown p, .stMarkdown li {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13.5px !important;
    color: #8eafc8 !important;
    line-height: 1.9 !important;
}
hr {
    border: none !important;
    height: 1px !important;
    background: linear-gradient(90deg, transparent, rgba(61,90,122,.35), transparent) !important;
    margin: 44px 0 !important;
}

/* ── DOWNLOAD BUTTON ── */
[data-testid="stDownloadButton"] > button {
    background: rgba(255,255,255,.04) !important;
    border: 1px solid rgba(16,185,129,.3) !important;
    color: #10b981 !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
    border-radius: 14px !important;
    width: 100% !important;
    height: 56px !important;
    transition: all .25s !important;
}
[data-testid="stDownloadButton"] > button:hover {
    background: rgba(16,185,129,.1) !important;
    border-color: rgba(16,185,129,.55) !important;
    box-shadow: 0 4px 30px rgba(16,185,129,.25) !important;
    transform: translateY(-2px) !important;
}

/* ── SELECTBOX ── */
.stSelectbox > div > div {
    background: rgba(255,255,255,.035) !important;
    border: 1px solid rgba(61,90,122,.45) !important;
    border-radius: 10px !important;
    color: #e2eaf4 !important;
}

/* ── SPINNER ── */
.stSpinner > div { border-top-color: #10b981 !important; }

/* ── HIDE CHROME ── */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }

[data-testid="column"] { padding: 0 10px !important; }
[data-testid="column"]:first-child { padding-left: 0 !important; }
[data-testid="column"]:last-child  { padding-right: 0 !important; }
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════
#  SIDEBAR — BRANDING ONLY
# ════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo">
        <div class="sidebar-logo-icon">🛡️</div>
        <div class="sidebar-logo-text">Cloud<span>Guard</span></div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style='margin-top:16px; padding-top:20px; border-top:1px solid rgba(61,90,122,.2);
    font-family:JetBrains Mono,monospace; font-size:10px; color:#2d4460; letter-spacing:1.5px;
    line-height:2;'>
    IAM permissions needed:<br>
    iam:ListUsers<br>
    iam:ListMFADevices<br>
    s3:ListAllMyBuckets<br>
    s3:GetBucketAcl<br>
    ec2:DescribeSecurityGroups<br>
    cloudtrail:DescribeTrails
    </div>
    """, unsafe_allow_html=True)


# ════════════════════════════════════════════════
#  MAIN — HEADER
# ════════════════════════════════════════════════
st.markdown("""
<div class="cg-badge">
    <div class="cg-badge-dot"></div>
    <div class="cg-badge-txt">System Online &nbsp;·&nbsp; IAM · S3 · EC2 · CloudTrail</div>
</div>

<div class="cg-hero">
    <div class="cg-icon">🛡️</div>
    <div class="cg-title">Cloud<span>Guard</span></div>
</div>

<div class="cg-subtitle">Automated AWS Security Auditing Platform</div>
<div class="cg-divider"></div>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════
#  MAIN — EMAIL INPUT
# ════════════════════════════════════════════════
st.markdown('<div class="section-label">Report Delivery</div>', unsafe_allow_html=True)
email = st.text_input("📧 Email address for report delivery", placeholder="you@company.com")

st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════
#  MAIN — AWS CREDENTIALS
# ════════════════════════════════════════════════
st.markdown('<div class="section-label">AWS Credentials</div>', unsafe_allow_html=True)

col_key, col_secret = st.columns(2)
with col_key:
    aws_key = st.text_input("🔑 Access Key ID", placeholder="AKIA...", key="aws_key")
with col_secret:
    aws_secret = st.text_input("🔒 Secret Access Key", placeholder="••••••••••••", key="aws_secret", type="password")

col_region, col_token = st.columns(2)
with col_region:
    aws_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "ap-south-1", "ap-southeast-1", "ap-southeast-2",
        "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "eu-north-1", "sa-east-1", "ca-central-1",
        "me-south-1", "af-south-1"
    ]
    aws_region = st.selectbox("🌍 Region", aws_regions, index=0, key="aws_region")
with col_token:
    aws_token = st.text_input("🎫 Session Token (optional)", placeholder="Paste STS/SSO token if needed...", key="aws_token")

# Build creds dict
has_creds = bool(aws_key.strip() and aws_secret.strip())
creds = {}
if has_creds:
    creds = {
        "aws_access_key_id":     aws_key.strip(),
        "aws_secret_access_key": aws_secret.strip(),
        "region_name":           aws_region,
    }
    if aws_token.strip():
        creds["aws_session_token"] = aws_token.strip()

st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

# ── Connection Status & Buttons ──
col_test, col_scan = st.columns(2)

with col_test:
    if has_creds:
        if st.button("🔗 Test Connection", key="test_conn"):
            with st.spinner("Testing AWS connection..."):
                try:
                    sts = boto3.client('sts', **creds)
                    identity = sts.get_caller_identity()
                    st.session_state["aws_conn_status"] = "ok"
                    st.session_state["aws_conn_info"]   = {
                        "Account": identity.get("Account", "—"),
                        "Arn":     identity.get("Arn", "—"),
                    }
                    st.rerun()
                except Exception as e:
                    st.session_state["aws_conn_status"] = "error"
                    st.session_state["aws_conn_err"]    = str(e)
                    st.rerun()

with col_scan:
    scan_btn = st.button("🚀 Initialize Scan")

# ── Connection Status Badge ──
if has_creds:
    if "aws_conn_status" not in st.session_state:
        st.session_state["aws_conn_status"] = None
        st.session_state["aws_conn_info"]   = {}

    status = st.session_state.get("aws_conn_status")
    if status == "ok":
        info = st.session_state.get("aws_conn_info", {})
        st.markdown(f"""
        <div class="conn-badge connected">
            <div class="conn-dot green"></div>Connected to AWS
        </div>
        <div class="account-info">
            Account: <span>{info.get('Account','—')}</span><br>
            User ARN: <span>{info.get('Arn','—')}</span><br>
            Region: <span>{aws_region}</span>
        </div>""", unsafe_allow_html=True)
    elif status == "error":
        st.markdown("""
        <div class="conn-badge disconnected">
            <div class="conn-dot red"></div>Connection Failed
        </div>""", unsafe_allow_html=True)
        st.error(st.session_state.get("aws_conn_err", "Unknown error"))

st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════
#  MAIN — SCAN LOGIC
# ════════════════════════════════════════════════
if scan_btn:

    if email.strip() == "":
        st.error("⚠️  Please enter a valid email address before scanning.")
    elif not has_creds:
        st.error("⚠️  Please enter your AWS Access Key and Secret to run a scan.")
    else:
        with st.spinner("🔍 Scanning AWS Environment..."):

            scan_errors = {}

            # Run each scanner independently so one missing permission doesn't stop the rest
            try:
                mfa_users = check_users_without_mfa(**creds)
            except Exception as e:
                mfa_users = []
                scan_errors["IAM"] = str(e)

            try:
                public_buckets = check_public_buckets(**creds)
            except Exception as e:
                public_buckets = []
                scan_errors["S3"] = str(e)

            try:
                open_security_groups = check_open_security_groups(**creds)
            except Exception as e:
                open_security_groups = []
                scan_errors["EC2"] = str(e)

            try:
                cloudtrail_status = check_cloudtrail_status(**creds)
            except Exception as e:
                cloudtrail_status = "Unknown"
                scan_errors["CloudTrail"] = str(e)

            score, risk = calculate_risk(
                mfa_users,
                public_buckets,
                open_security_groups,
                cloudtrail_status
            )

            # Generate PDF
            pdf_path = generate_pdf(
                score,
                risk,
                mfa_users,
                public_buckets,
                open_security_groups,
                cloudtrail_status
            )

            # Store everything in session_state so it persists across reruns
            st.session_state["scan_results"] = {
                "score": score,
                "risk": risk,
                "mfa_users": mfa_users,
                "public_buckets": public_buckets,
                "open_security_groups": open_security_groups,
                "cloudtrail_status": cloudtrail_status,
                "scan_errors": scan_errors,
                "pdf_path": pdf_path,
                "email": email.strip(),
            }

        if scan_errors:
            st.warning(f"⚠️  Scan completed with {len(scan_errors)} permission error(s). Results shown for accessible services.")
        else:
            st.success("✅ Live AWS scan completed successfully.")


# ════════════════════════════════════════════════
#  MAIN — DISPLAY RESULTS (persists across reruns)
# ════════════════════════════════════════════════
if "scan_results" in st.session_state:
    r = st.session_state["scan_results"]
    score = r["score"]
    risk = r["risk"]
    mfa_users = r["mfa_users"]
    public_buckets = r["public_buckets"]
    open_security_groups = r["open_security_groups"]
    cloudtrail_status = r["cloudtrail_status"]
    scan_errors = r["scan_errors"]
    pdf_path = r["pdf_path"]
    report_email = r["email"]

    # Show per-service permission errors
    if scan_errors:
        for svc, err in scan_errors.items():
            st.error(f"❌ **{svc}**: {err}")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── METRICS ──
    st.markdown('<div class="section-label">Scan Results</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("🔐 Security Score", f"{score}/100")
    with col2:
        st.metric("⚠️ Risk Level", risk)

    st.markdown("---")

    # ── FINDINGS ──
    st.subheader("🚨 Security Findings")
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        iam_items = ""
        if mfa_users:
            for u in mfa_users:
                iam_items += f'<div class="finding-item"><div class="fi-dot"></div>{u}</div>'
        else:
            iam_items = '<div class="finding-ok">✅ No issues found</div>'

        s3_items = ""
        if public_buckets:
            for b in public_buckets:
                s3_items += f'<div class="finding-item"><div class="fi-dot"></div>{b}</div>'
        else:
            s3_items = '<div class="finding-ok">✅ No issues found</div>'

        st.markdown(f"""
        <div class="finding-card">
            <div class="finding-card-title"><span class="fc-icon">🔑</span>IAM — Users Without MFA</div>
            {iam_items}
        </div>
        <div class="finding-card">
            <div class="finding-card-title"><span class="fc-icon">🪣</span>S3 — Public Buckets</div>
            {s3_items}
        </div>
        """, unsafe_allow_html=True)

    with col2:
        ec2_items = ""
        if open_security_groups:
            for sg in open_security_groups:
                label = f"{sg.get('GroupName','?')} — Port {sg.get('Port','?')}" if isinstance(sg, dict) else str(sg)
                ec2_items += f'<div class="finding-item"><div class="fi-dot"></div>{label}</div>'
        else:
            ec2_items = '<div class="finding-ok">✅ No issues found</div>'

        ct_color = "#10b981" if str(cloudtrail_status).lower() not in ("disabled","cloudtrail disabled","false","none") else "#ef4444"
        ct_html  = f'<div style="font-family:JetBrains Mono,monospace;font-size:15px;font-weight:600;color:{ct_color};padding:10px 0 2px;">{cloudtrail_status}</div>'

        st.markdown(f"""
        <div class="finding-card">
            <div class="finding-card-title"><span class="fc-icon">🖥️</span>EC2 — Open Security Groups</div>
            {ec2_items}
        </div>
        <div class="finding-card">
            <div class="finding-card-title"><span class="fc-icon">📋</span>CloudTrail Status</div>
            {ct_html}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # ── REPORT & DELIVERY ──
    st.markdown('<div class="section-label">Report &amp; Delivery</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        if st.button("📧 Send Report via Email"):
            with st.spinner("📨 Sending email..."):
                try:
                    send_email(report_email, pdf_path)
                    st.success(f"✅ Report sent successfully to {report_email}!")
                except Exception as e:
                    st.error(f"❌ Email failed: {e}")

    with col2:
        with open(pdf_path, "rb") as file:
            st.download_button(
                "⬇️ Download PDF Report",
                data=file,
                file_name="cloudguard_report.pdf"
            )