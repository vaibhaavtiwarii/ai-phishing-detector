import streamlit as st
import joblib
import pandas as pd
from scipy.sparse import hstack
from features import extract_features  # Imports your upgraded lexical engine!

# --- 1. SET UP THE PAGE ---
st.set_page_config(
    page_title="AI Phishing Threat Engine",
    page_icon="🛡️",
    layout="centered"
)

# --- 2. LOAD OUR HYBRID PIPELINE ARTIFACTS ---
@st.cache_resource
def load_pipeline():
    # Loads the LightGBM classifier, dual vectorizers, and lexical columns
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

# --- 3. TITLE & DESCRIPTION ---
st.title("🛡️ AI-Powered Phishing Threat Detection Engine")
st.markdown("""
This engine uses an **Industry-Grade Dual-Engine LightGBM Classifier** trained on 120,000+ active web addresses.
It splits URLs to run dedicated Domain and Path TF-IDF pipelines alongside 18 high-fidelity lexical indicators.
""")
st.write("---")

if pipeline_loaded:
    st.subheader("🔗 Paste URL for Live Threat Analysis")
    user_url = st.text_input(
        "Enter Web Address:",
        placeholder="https://example-phishing-login.com"
    )

    # --- 4. RUN HYBRID PREDICTION ---
    if st.button("🛡️ Audit Website Risk Score", use_container_width=True):
        if not user_url.strip():
            st.warning("Please enter a valid URL first!")
        else:
            with st.spinner("Decomposing URL and auditing threat matrices..."):
                # Step A: Run Upgraded Lexical Extraction & URL Decomposition
                raw_lexical, domain_str, path_str = extract_features(user_url)
                
                # Show extracted features in an expander for analyst review
                with st.expander("🔍 Extracted URL Structural & Entropy Indicators"):
                    st.write({
                        "domain": domain_str,
                        "path": path_str,
                        **raw_lexical
                    })

                # Step B: Run Dual TF-IDF Engines
                domain_tfidf = vec_domain.transform([domain_str])
                path_tfidf = vec_path.transform([path_str])

                # Convert lexical features to DataFrame in the correct order
                lexical_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)

                # Step C: Fuse Domain Tokens + Path Tokens + Structural Features
                fused_features = hstack([domain_tfidf, path_tfidf, lexical_df.values]).tocsr()

                # Step D: Run LightGBM Prediction
                prediction = model.predict(fused_features)[0]
                probabilities = model.predict_proba(fused_features)[0]

                # Index 0 is Legitimate (0), Index 1 is Phishing (1)
                phishing_risk = probabilities[1] * 100

                st.write("---")
                st.subheader("📊 Audit Assessment Results")

                # Set threshold: alert if predicted phishing (1) OR risk score > 50%
                if prediction == 1 or phishing_risk > 50:
                    st.error(f"🚨 **ALERT: High Phishing Risk Detected!**")
                    st.metric(label="Calculated Phishing Risk Score", value=f"{phishing_risk:.1f}%")
                    st.progress(int(phishing_risk))
                    st.warning("""
                    ⚠️ **Security Analyst Recommendation:**
                    * Do **NOT** input any credentials or personal information on this page.
                    * The URL contains dangerous sub-word combinations or structural patterns heavily associated with active social-engineering campaigns.
                    """)
                else:
                    st.success("✅ **STATUS: Website Appears Legitimate**")
                    st.metric(label="Calculated Phishing Risk Score", value=f"{phishing_risk:.1f}%")
                    st.progress(int(phishing_risk))
                    st.info("""
                    🛡️ **Security Auditor Note:**
                    * The URL structure exhibits standard benign traits.
                    * Always manually double-check domain spellings in the address bar before logging in.
                    """)
# Force trigger model sync - v2
