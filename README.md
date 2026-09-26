#  AI-Powered Phishing Threat Detection Engine

An end-to-end, hybrid Machine Learning pipeline and interactive security dashboard designed to detect modern phishing URLs in real-time. This project bypasses the limitations of traditional rule-based blacklists by utilizing a **Random Forest Classifier** trained on live, raw web address lexical structures.

**Real-World Test Accuracy:** 83.80% (Precision: 0.8315 | Recall: 0.8478)  
⚡ **Throughput:** ~18,000 URLs/sec parallel feature extraction across 14 CPU cores

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

##  Performance & Benchmark Metrics (80,000 Samples)

The classifier was trained on a strictly balanced dataset of **80,000 real-world raw URLs** (40,000 benign, 40,000 confirmed malicious) evaluated on a held-out test set of 16,000 samples:

```text
               precision    recall  f1-score   support

Legitimate (0)     0.8447    0.8283    0.8364      8000
  Phishing (1)     0.8315    0.8478    0.8396      8000

      accuracy                         0.8380     16000
     macro avg     0.8381    0.8380    0.8380     16000
  weighted avg     0.8381    0.8380    0.8380     16000