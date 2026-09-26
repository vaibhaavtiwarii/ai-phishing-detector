#  AI-Powered Phishing Threat Detection Engine

An end-to-end, hybrid Machine Learning pipeline and interactive security dashboard designed to detect modern phishing URLs in real-time. This project bypasses the limitations of traditional rule-based blacklists by utilizing a **Random Forest Classifier** trained on live, raw web address lexical structures.

 **Real-World Test Accuracy:** 82.35% (Precision: 0.82 | Recall: 0.83)

---

##  Key Architectural Features

Unlike naive academic models that rely on unextractable network metadata (such as global web traffic ranking), this engine is built strictly on **15 clean, 100% extractable lexical indicators** parsed in real-time from raw URL inputs:

*   **Entropy & Structural Features:** URL length, subdomain depth (`subdomain_count`), path length, and specific character distributions (`-`, `.`, `@`, `?`, `=`, `/`).
*   **Brand Impersonation Checks:** Scans domain matrices for high-risk social-engineering keywords (e.g., `login`, `verify`, `secure`, `paypal`, `admin`).
*   **Protocol Security Auditor:** Analyzes state protocols (HTTP vs. HTTPS) alongside anomalous Top-Level Domains (TLDs).
*   **IP Detection:** Flags raw IPv4 addresses attempting to mask brand identities.

---

##  Tech Stack & Libraries

*   **Language:** Python 3.12 (64-bit)
*   **Machine Learning:** Scikit-learn (Random Forest Classifier)
*   **Data Processing:** Pandas, NumPy
*   **Dashboard UI:** Streamlit (Interactively deployed for security analysts)
*   **Model Serialization:** Joblib

---

##  Performance & Benchmark Metrics

The classifier was trained on a balanced set of **20,000 real-world raw URLs** (50% benign, 50% confirmed malicious) sourced from active threat feeds:

```text
  Classification Report:

                precision    recall  f1-score   support

Legitimate (0)       0.83      0.81      0.82      2000
  Phishing (1)       0.82      0.83      0.83      2000

      accuracy                           0.82      4000
