import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import os
import urllib.parse
import joblib
import pandas as pd
from scipy.sparse import hstack

from features import extract_features
from advisor import generate_security_advisory

# --- 1. CONFIGURATION (Cloud Secrets + Local Fallback) ---
IMAP_SERVER = "imap.gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

# Pulls securely from GitHub Actions secrets if running in the cloud, otherwise falls back to your local credentials
GMAIL_USER = os.getenv("GMAIL_USER", "vaibhavt.7895@gmail.com")
GMAIL_APP_PASS = os.getenv("GMAIL_APP_PASS", "giczzncpaqlkaluh")

# Enterprise Authority Allowlist & Trusted CDNs
TOP_VERIFIED_ROOTS = {
    # Core Tech & Identity Authorities
    "facebook.com", "fb.com", "google.com", "google.co.in", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "amazon.in", "netflix.com",
    "github.com", "linkedin.com", "instagram.com", "twitter.com", "x.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "zoom.us", "paypal.com",
    "spotify.com", "adobe.com", "dropbox.com", "stackoverflow.com", 
    "invertisuniversity.ac.in", "selfstudys.com",
    
    # Official Banking Authorities (State Bank of India)
    "sbi.co.in", "sbi.bank.in", "sbi.bank", "onlinesbi.sbi", "sbi",
    
    # Trusted Global CDNs & Hosted Resource Domains
    "gstatic.com", "googleapis.com", "googleusercontent.com", "google-analytics.com",
    "githubusercontent.com", "aws.amazon.com", "cloudfront.net", "akamaihd.net",
    "licdn.com", "media.licdn.com", "static.licdn.com", "github.githubassets.com",
    "w3.org", "cdn.bfldr.com", "library.iterable.com",
    
    # Verified ESP (Email Service Provider) Tracking Redirects
    "sparkpostmail.com", "sparkpostmail1.com", "sendgrid.net", "mailchimp.com",
    "codecademy.com", "links.codecademy.com"
}

def get_root_domain(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str if '://' in url_str else 'http://' + url_str)
        domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower().split('/')[0]
        parts = domain.split('.')
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain
    except Exception:
        return ""

# --- 2. LOAD PIPELINE ARTIFACTS ---
print("📦 Loading 96.27% Dual-Engine LightGBM Pipeline...")
pipeline = joblib.load("phishing_hybrid_pipeline.pkl")
model = pipeline['model']
vec_domain = pipeline['vec_domain']
vec_path = pipeline['vec_path']
lexical_columns = pipeline['lexical_columns']
print("✅ Threat engine ready.\n")

def extract_urls(text):
    """Extracts all HTTP/HTTPS links from email body text and HTML."""
    pattern = r'https?://[^\s<>"\',;]+'
    return list(set(re.findall(pattern, text)))

def audit_url(url_str):
    """Evaluates a single URL against Allowlist + LightGBM."""
    root_domain = get_root_domain(url_str)
    
    # Tier 1: Allowlist Check
    if root_domain in TOP_VERIFIED_ROOTS:
        return {
            "url": url_str,
            "is_phishing": False,
            "risk_score": 0.0,
            "tier": "Enterprise Allowlist",
            "threat_type": "Verified Safe Asset",
            "summary": f"Verified infrastructure parent domain '{root_domain}' is registered in our authority database.",
            "what_to_do": ["Proceed with normal safe interaction."],
            "what_not_to_do": ["No actions needed."]
        }
    
    # Tier 2: Machine Learning Inference
    raw_lexical, domain_str, path_str = extract_features(url_str)
    dom_tf = vec_domain.transform([domain_str])
    path_tf = vec_path.transform([path_str])
    lex_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)
    
    fused = hstack([dom_tf, path_tf, lex_df.values]).tocsr()
    pred = int(model.predict(fused)[0])
    risk = float(model.predict_proba(fused)[0][1] * 100)
    is_phish = bool(pred == 1 or risk > 50)
    
    adv = generate_security_advisory(
        url_str=url_str,
        is_phishing=is_phish,
        risk_score=risk,
        heuristics=raw_lexical,
        domain_str=domain_str,
        root_domain=root_domain,
        is_allowlisted=False
    )
    
    return {
        "url": url_str,
        "is_phishing": is_phish,
        "risk_score": round(risk, 2),
        "tier": "LightGBM ML
