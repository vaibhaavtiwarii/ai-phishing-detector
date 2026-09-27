import streamlit as st
import joblib
import pandas as pd
import urllib.parse
from scipy.sparse import hstack
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
                
                with st.expander("🔍 Extracted URL Structural & Entropy Indicators"):
                    st.write({
                        "domain": domain_str,
                        "path": path_str,
                        "root_domain": root_domain,
                        **raw_lexical
                    })

                # --- TIER 1: VERIFIED AUTHORITY ALLOWLIST CHECK ---
                if root_domain in TOP_VERIFIED_ROOTS:
                    st.write("---")
                    st.subheader("📊 Audit Assessment Results")
                    st.success("✅ **STATUS: Verified Global Authority (Zero Risk)**")
                    st.metric(label="Calculated Phishing Risk Score (%)", value=0.0)
                    st.progress(0)
                    st.info(f"""
                    🛡️ **Enterprise Allowlist Protection:**
                    * **Verified Root Authority:** `{root_domain}` is recognized in the global trust registry.
                    * Bypasses probabilistic scoring to eliminate false alarms on trusted infrastructure.
                    """)
                
                else:
                    # --- TIER 2: DUAL-ENGINE LIGHTGBM MACHINE LEARNING INFERENCE ---
                    domain_tfidf = vec_domain.transform([domain_str])
                    path_tfidf = vec_path.transform([path_str])
                    lexical_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)

                    fused_features = hstack([domain_tfidf, path_tfidf, lexical_df.values]).tocsr()
                    prediction = model.predict(fused_features)[0]
                    probabilities = model.predict_proba(fused_features)[0]
                    phishing_risk = probabilities[1] * 100

                    st.write("---")
                    st.subheader("📊 Audit Assessment Results")

                    if prediction == 1 or phishing_risk > 50:
                        st.error(f"🚨 **ALERT: High Phishing Risk Detected!**")
                        st.metric(label="Calculated Phishing Risk Score (%)", value=float(f"{phishing_risk:.1f}"))
                        st.progress(int(phishing_risk))
                        st.warning("""
                        ⚠️ **Security Analyst Recommendation:**
                        * Do **NOT** input any credentials or personal information on this page.
                        * The URL contains anomalous character tokens or deceptive structural depth typical of credential theft.
                        """)
                    else:
                        st.success("✅ **STATUS: Website Appears Legitimate**")
                        st.metric(label="Calculated Phishing Risk Score (%)", value=float(f"{phishing_risk:.1f}"))
                        st.progress(int(phishing_risk))
                        st.info("""
                        🛡️ **Security Auditor Note:**
                        * The URL structure exhibits standard benign traits.
                        * Always manually double-check domain spellings in the address bar before logging in.
                        """)
