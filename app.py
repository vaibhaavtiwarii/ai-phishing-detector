import streamlit as st
import joblib
import pandas as pd
import urllib.parse
from scipy.sparse import hstack
from advisor import generate_security_advisory
from features import extract_features

# --- 1. SET UP THE PAGE ---
st.set_page_config(
    page_title="AI Phishing Threat Engine",
    page_icon="🛡️",
    layout="centered"
)

# --- 2. ENTERPRISE AUTHORITY ALLOWLIST ---
TOP_VERIFIED_ROOTS = {
    "facebook.com", "fb.com", "google.com", "google.co.in", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "amazon.in", "netflix.com",
    "github.com", "linkedin.com", "instagram.com", "twitter.com", "x.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "zoom.us", "paypal.com",
    "spotify.com", "adobe.com", "dropbox.com", "stackoverflow.com", "invertisuniversity.ac.in"
}

def get_root_domain(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str if '://' in url_str else 'http://' + url_str)
        domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower().split('/')[0]
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            return ".".join(domain_parts[-2:])
        return domain
    except Exception:
        return ""

# --- 3. LOAD OUR HYBRID PIPELINE ARTIFACTS ---
@st.cache_resource
def load_pipeline():
    return joblib.load("phishing_hybrid_pipeline.pkl")

try:
    pipeline = load_pipeline()
    model = pipeline['model']
    vec_domain = pipeline['vec_domain']
    vec_path = pipeline['vec_path']
    lexical_columns = pipeline['lexical_columns']
    pipeline_loaded = True
except Exception as e:
    pipeline_loaded = False
    st.error(f"Error loading hybrid pipeline: {e}")

# --- 4. TITLE & DESCRIPTION ---
st.title("🛡️ AI-Powered Phishing Threat Detection Engine")
st.markdown("""
This engine uses an **Industry-Grade Dual-Engine LightGBM Classifier** combined with an 
**Enterprise Authority Allowlist** to evaluate web addresses in real-time.
""")
st.write("---")

if pipeline_loaded:
    st.subheader("🔗 Paste URL for Live Threat Analysis")
    user_url = st.text_input(
        "Enter Web Address:",
        placeholder="https://example-phishing-login.com"
    )

    if st.button("🛡️ Audit Website Risk Score", use_container_width=True):
        if not user_url.strip():
            st.warning("Please enter a valid URL first!")
        else:
            with st.spinner("Decomposing URL and auditing threat matrices..."):
                raw_lexical, domain_str, path_str = extract_features(user_url)
                root_domain = get_root_domain(user_url)
                is_allowlisted = root_domain in TOP_VERIFIED_ROOTS
                
                with st.expander("🔍 Extracted URL Structural & Entropy Indicators"):
                    st.write({
                        "domain": domain_str,
                        "path": path_str,
                        "root_domain": root_domain,
                        **raw_lexical
                    })

                # --- EXTRACT THREAT CLASS & RISKS ---
                if is_allowlisted:
                    prediction = 0
                    phishing_risk = 0.0
                else:
                    domain_tfidf = vec_domain.transform([domain_str])
                    path_tfidf = vec_path.transform([path_str])
                    lexical_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)

                    fused_features = hstack([domain_tfidf, path_tfidf, lexical_df.values]).tocsr()
                    prediction = model.predict(fused_features)[0]
                    probabilities = model.predict_proba(fused_features)[0]
                    phishing_risk = float(probabilities[1] * 100)

                # --- TIER-BASED SECURITY ADVISORY GENERATOR ---
                advisory = generate_security_advisory(
                    url_str=user_url,
                    is_phishing=(prediction == 1 or phishing_risk > 50),
                    risk_score=phishing_risk,
                    heuristics=raw_lexical,
                    domain_str=domain_str,
                    root_domain=root_domain,
                    is_allowlisted=is_allowlisted
                )

                st.write("---")
                st.subheader(f"📊 Assessment: {advisory['threat_type']}")

                if is_allowlisted:
                    st.success("✅ **STATUS: Verified Global Authority**")
                    st.metric(label="Calculated Phishing Risk Score (%)", value="0.0")
                    st.progress(0)
                elif prediction == 1 or phishing_risk > 50:
                    st.error("🚨 **ALERT: Active Threat Detected**")
                    st.metric(label="Calculated Phishing Risk Score (%)", value=f"{phishing_risk:.1f}")
                    st.progress(int(phishing_risk))
                else:
                    st.success("✅ **STATUS: Low Risk Profile**")
                    st.metric(label="Calculated Phishing Risk Score (%)", value=f"{phishing_risk:.1f}")
                    st.progress(int(phishing_risk))

                st.markdown(f"**Diagnostic Summary:** *{advisory['summary']}*")
                st.write("---")

                # Parallel Display Columns for Actions
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### 🟢 What To Do")
                    for item in advisory['what_to_do']:
                        st.markdown(f"* {item}")

                with col2:
                    st.markdown("### 🔴 What NOT To Do")
                    for item in advisory['what_not_to_do']:
                        st.markdown(f"* {item}")
