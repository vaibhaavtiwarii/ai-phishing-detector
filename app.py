import streamlit as st
import joblib
import pandas as pd
import numpy as np
from features import extract_features  # We import our lexical feature engine!

# --- 1. SET UP THE PAGE ---
st.set_page_config(
    page_title="AI Phishing Threat Engine",
    page_icon="🛡️",
    layout="centered"
)

# --- 2. LOAD OUR TRAINED MODEL ---
@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

try:
    model = load_model()
    model_loaded = True
except Exception as e:
    model_loaded = False
    st.error(f"Error loading model: {e}")

# --- 3. TITLE & DESCRIPTION ---
st.title("🛡️ AI-Powered Phishing Threat Detection Engine")
st.markdown("""
This engine uses a **Random Forest Classifier** to analyze URLs in real-time.
Paste a URL below to run our hybrid lexical feature extractor and evaluate its risk score.
""")
st.write("---")

if model_loaded:
    st.subheader("🔗 Paste URL for Live Threat Analysis")
    user_url = st.text_input(
        "Enter Web Address:",
        placeholder="https://example-phishing-login.com"
    )

    # --- 4. RUN PREDICTION ON USER INPUT ---
    if st.button("🛡️ Audit Website Risk Score", use_container_width=True):
        if not user_url.strip():
            st.warning("Please enter a valid URL first!")
        else:
            # Step A: Extract live lexical features
            raw_features = extract_features(user_url)

            with st.expander("🔍 Extracted URL Lexical Indicators"):
                st.write(raw_features)

            # Step B: Map extracted features to the 30-feature schema
            feature_values = np.ones(30)  # Default to 1 (safe)

            # --- SMARTER MAPPING LOGIC ---
            feature_values[0] = -1 if raw_features['has_ip'] else 1
            feature_values[1] = -1 if raw_features['url_length'] >= 54 else (0 if 40 <= raw_features['url_length'] < 54 else 1)
            feature_values[5] = -1 if raw_features['count_hyphens'] > 0 else 1
            feature_values[6] = -1 if raw_features['domain_dots'] >= 3 else (0 if raw_features['domain_dots'] == 2 else 1)
            feature_values[7] = 1 if raw_features['is_https'] else -1

            # --- THE FIX FOR THE WARNING ---
            # Define the exact 30 feature names the model was trained on
            feature_names = [
                'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
                'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
                'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
                'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
                'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
                'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
                'Statistical_report'
            ]

            # Construct a single-row DataFrame with the correct feature names
            prediction_df = pd.DataFrame([feature_values], columns=feature_names)

            # Step C: Run prediction cleanly with the named DataFrame
            prediction = model.predict(prediction_df)[0]
            probabilities = model.predict_proba(prediction_df)[0]
            phishing_risk = probabilities[0] * 100

            st.write("---")
            st.subheader("📊 Audit Assessment Results")

            if prediction == -1 or phishing_risk > 40:
                st.error(f"🚨 **ALERT: High Phishing Risk Detected!**")
                st.metric(label="Calculated Phishing Risk Score", value=f"{phishing_risk:.1f}%")
                st.progress(int(phishing_risk))
                st.warning("""
                ⚠️ **Security Analyst Recommendation:**
                * Do **NOT** input any credentials or personal information on this page.
                * The URL contains anomalies like suspicious domain padding or unsecured transfer protocols.
                """)
            else:
                st.success("✅ **STATUS: Website Appears Legitimate**")
                st.metric(label="Calculated Phishing Risk Score", value=f"{phishing_risk:.1f}%")
                st.progress(int(phishing_risk))
                st.info("""
                🛡️ **Security Auditor Note:**
                * The URL metrics align with standard safe web structures.
                * Always double-check domain spellings manually.
                """)
