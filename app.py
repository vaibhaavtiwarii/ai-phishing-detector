import streamlit as st
import joblib
import pandas as pd
from features import extract_features  # Import your upgraded feature engine!

# --- 1. SET UP THE PAGE ---
st.set_page_config(
    page_title="AI Phishing Threat Engine",
    page_icon="🛡️",
    layout="centered"
)

# --- 2. LOAD OUR REAL-WORLD MODEL ---
@st.cache_resource
def load_model():
    # Load the brand new, 15-feature real-world model
    return joblib.load("phishing_model_real.pkl")

try:
    model = load_model()
    model_loaded = True
except Exception as e:
    model_loaded = False
    st.error(f"Error loading model: {e}")

# --- 3. TITLE & DESCRIPTION ---
st.title("🛡️ AI-Powered Phishing Threat Detection Engine")
st.markdown("""
This engine uses a **Real-World Random Forest Classifier** trained on 20,000+ raw, active web addresses.
Paste any URL below to run our hybrid lexical feature extractor and calculate its real threat score.
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
            # Step A: Extract live lexical features from raw user URL
            raw_features = extract_features(user_url)

            with st.expander("🔍 Extracted URL Lexical Indicators"):
                st.write(raw_features)

            # Step B: Prepare features to match the exact 15-feature structure of the new model
            # Construct a DataFrame with the exact same keys returned by features.py
            prediction_df = pd.DataFrame([raw_features])

            # Step C: Run Scikit-learn Prediction cleanly with matching schema
            prediction = model.predict(prediction_df)[0]
            probabilities = model.predict_proba(prediction_df)[0]

            # In the new model: Index 0 is Legitimate (0), Index 1 is Phishing (1)
            phishing_risk = probabilities[1] * 100

            st.write("---")
            st.subheader("📊 Audit Assessment Results")

            # We trigger an alert if the model predicts Phishing (1) OR if the calculated risk exceeds 50%
            if prediction == 1 or phishing_risk > 50:
                st.error(f"🚨 **ALERT: High Phishing Risk Detected!**")
                st.metric(label="Calculated Phishing Risk Score", value=f"{phishing_risk:.1f}%")
                st.progress(int(phishing_risk))
                st.warning("""
                ⚠️ **Security Analyst Recommendation:**
                * Do **NOT** input any credentials, tokens, or personal information on this page.
                * This address displays classic social-engineering lexical features (e.g., suspicious keyword structures, unusual domain depth, or hyphen-padding).
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
