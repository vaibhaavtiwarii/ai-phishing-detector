import streamlit as st
import joblib
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
Paste a URL below to run our hybrid lexical feature extractor and evaluate the risk score.
""")

st.write("---")

if model_loaded:
    st.subheader("🔗 Paste URL for Live Threat Analysis")
    
    # Text input for the raw URL
    user_url = st.text_input(
        "Enter Web Address:", 
        placeholder="https://example-phishing-login.com"
    )

    # --- 4. RUN PREDICTION ON USER INPUT ---
    if st.button("🛡️ Audit Website Risk Score", use_container_width=True):
        if not user_url.strip():
            st.warning("Please enter a valid URL first!")
        else:
            # Step A: Extract live lexical features using features.py
            raw_features = extract_features(user_url)
            
            # Show the extracted metrics to the user for education/transparency
            with st.expander("🔍 Extracted URL Lexical Indicators"):
                st.write(raw_features)
            
            # Step B: Map extracted features to the 30-feature schema expected by the model
            features = np.ones(30) # Safe default mapping
            
            # Map SSL Certificate (HTTPS)
            # If our URL starts with https, set index 7 to 1 (safe), else set to -1 (suspicious)
            features[7] = 1 if raw_features['is_https'] == 1 else -1
            
            # Map Prefix/Suffix (presence of dashes in domain)
            features[5] = -1 if raw_features['count_hyphens'] > 0 else 1
            
            # Map Sub-domains
            # If domain dots > 2, treat it as multiple subdomains (-1), else standard (1)
            features[6] = -1 if raw_features['domain_dots'] > 2 else (0 if raw_features['domain_dots'] == 2 else 1)
            
            # Map URL Length (If long, flag as suspicious)
            features[1] = -1 if raw_features['url_length'] > 75 else (0 if raw_features['url_length'] > 54 else 1)
            
            # Map IP Address presence
            features[0] = -1 if raw_features['has_ip'] == 1 else 1

            # Step C: Run Scikit-learn Prediction
            prediction_input = features.reshape(1, -1)
            prediction = model.predict(prediction_input)[0]
            probabilities = model.predict_proba(prediction_input)[0]
            
            # Calculate risk percentage
            phishing_risk = probabilities[0] * 100

            st.write("---")
            st.subheader("📊 Audit Assessment Results")

            if prediction == -1 or phishing_risk > 50:
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
