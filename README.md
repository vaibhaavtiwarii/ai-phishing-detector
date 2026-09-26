# 🛡️ AI-Powered Phishing Threat Detection Engine (Dual-Engine LightGBM)

An end-to-end, high-performance cybersecurity pipeline and interactive threat intelligence dashboard designed to classify phishing and malicious URLs in real-time. Built with a **Dual-Engine LightGBM Architecture** combining character-level NLP with lexical, mathematical, and heuristic indicators trained on **120,000 real-world URLs**.

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![LightGBM](https://img.shields.io/badge/Model-LightGBM-brightgreen)](https://lightgbm.readthedocs.io/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📊 Benchmark & Evaluation Metrics (120,000 URLs)

Evaluated on an independent, strictly held-out test split of **18,000 unseen URLs** (9,000 Legitimate, 9,000 Confirmed Phishing):

```text
======================================================================
🎯 FINAL TEST ACCURACY : 96.27%
📈 ROC-AUC SCORE       : 0.9937
======================================================================
📋 Detailed Classification Report:

                precision    recall  f1-score   support

Legitimate (0)     0.9578    0.9680    0.9629      9000
  Phishing (1)     0.9677    0.9573    0.9625      9000

      accuracy                         0.9627     18000
     macro avg     0.9627    0.9627    0.9627     18000
  weighted avg     0.9627    0.9627    0.9627     18000

  ```
---

### 🧠 Architectural Evolution & Breakthroughs
Traditional machine learning classifiers evaluate uniform character counts across an entire URL string, diluting localized threat indicators. This engine implements a multi-tiered feature decomposition pipeline:
```text
                              [ Raw Incoming URL ]
                                       │
           ┌───────────────────────────┴───────────────────────────┐
           ▼                                                       ▼
   [ Domain Parsing ]                                      [ Path Parsing ]
           │                                                       │
           ├─► Domain TF-IDF (2–4 n-grams, 3k feats)               ├─► Path TF-IDF (3–5 n-grams, 2k feats)
           ├─► Shannon Entropy Calculations                        └─► Directory Depth & Param Analysis
           ├─► Brand Spoofing Cross-Checks (e.g. PayPal/Canva)
           └─► High-Risk TLD & DGA Vowel-to-Consonant Ratios
                                       │
                                       ▼
                       [ Fused Matrix: 5,020 Features ]
                                       │
                                       ▼
                [ LightGBM Classifier (300 Gradient Boosted Trees) ]
                                       │
                                       ▼
                         🎯 Real-Time Threat Score (<3ms)

        ``` 
        
  ```

**1. Dual-Engine Character-Level NLP**
Domain Engine (3,000 tokens): Isolates the Fully Qualified Domain Name (FQDN) using character 2-grams through 4-grams to detect subtle typosquatting and brand impersonation (e.g., paypa1, secure-login).

Path Engine (2,000 tokens): Evaluates URI paths using 3-grams through 5-grams to capture credential-harvesting endpoints (e.g., /wp-content/login.php, ?auth_token=).

**2. Information Theory & Heuristic Vectors**
Shannon Information Entropy (H): Measures algorithmic randomness in domain strings to expose automated Domain Generation Algorithms (DGAs).

Linguistic DGA Ratio: Analyzes vowel-to-consonant ratios to detect non-human, machine-generated subdomains.

Target Brand Hijacking: Identifies deceptive brand keywords hosted on legitimate cloud infrastructure (e.g., Canva, Webflow, Railway).

High-Risk TLD Penalties: Dynamically penalizes top-level domains statistically overrepresented in phishing feeds (.sbs, .online, .top, .xyz).

**3. LightGBM Gradient Boosting**
Migrated from static Random Forests to Microsoft LightGBM (300 estimators, 63 leaves). Unlike independent decision trees, gradient boosting builds sequential trees where each subsequent tree optimizes the residual errors of preceding iterations.

---

#### ⚡ Concurrency & Performance Benchmarks
Feature Extraction Throughput: ~25,000 URLs/sec via Python concurrent.futures multiprocessing utilizing all available CPU cores.

Inference Latency: Sub-3 millisecond response times per URL, rendering the pipeline viable for real-time DNS filtering and inline email proxy inspection.

Storage Footprint: Pipeline artifacts are compressed via Zlib (compress=3), packaging the 5,020-dimensional model into an optimized footprint under 30 MB.

---


##### 🛠️ Quickstart Installation & Local Setup
1. Clone & Set Up Environment
git clone https://github.com/vaibhaavtiwarii/ai-phishing-detector.git
cd ai-phishing-detector
python -m venv venv
2. Activate Virtual Environment
Windows (PowerShell):powershell.\venv\Scripts\activate
macOS / Linux:source venv/bin/activate

3. Install Dependencies
pip install pandas numpy scikit-learn lightgbm streamlit joblib scipy
4. Execute Pipeline & App
bash
1. Retrain the model on 120,000 balanced raw URLs
python train.py

2. Launch the interactive Security Operations Dashboard
streamlit run app.py


##### 📜 License
Distributed under the MIT License. See [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) for more information.


