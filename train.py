import pandas as pd
import numpy as np
import os
import time
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from scipy.sparse import hstack
import joblib
from lightgbm import LGBMClassifier

from features import extract_features
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

DATA_FILENAME = "raw_urldata.csv"

def extract_url_worker(url):
    try:
        feats, dom, path = extract_features(str(url))
        return {'feats': feats, 'domain': dom, 'path': path}
    except Exception:
        return None

def main():
    print("=" * 70)
    print("⚡ STATE-OF-THE-ART DUAL-ENGINE LIGHTGBM PIPELINE (120k URLs)")
    print("=" * 70)

    # --- 1. LOAD DATASET ---
    print("\n📖 Loading dataset...")
    df = pd.read_csv(DATA_FILENAME)
    df.columns = ['url', 'label']
    df['result'] = df['label'].apply(lambda x: 1 if str(x).lower() == 'bad' else 0)
    df = df[['url', 'result']].dropna().drop_duplicates()

    # Balanced 120,000 URLs
    phish_samples = df[df['result'] == 1]
    benign_samples = df[df['result'] == 0]
    target_per_class = min(60000, len(phish_samples), len(benign_samples))

    phish_sub = phish_samples.sample(n=target_per_class, random_state=42)
    benign_sub = benign_samples.sample(n=target_per_class, random_state=42)
    dataset = pd.concat([phish_sub, benign_sub]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"📊 Training corpus: {len(dataset):,} balanced URLs")

    # --- 2. TRAIN / TEST SPLIT ---
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        dataset['url'].astype(str),
        dataset['result'].values,
        test_size=0.15,
        random_state=42,
        stratify=dataset['result'].values
    )

    # --- 3. MULTI-CORE PARALLEL EXTRACTION ---
    cores = multiprocessing.cpu_count()
    print(f"\n⚡ Extracting domain, path, and 18 structural features across {cores} CPU cores...")
    t0 = time.time()

    with ProcessPoolExecutor(max_workers=cores) as executor:
        train_results = list(executor.map(extract_url_worker, X_train_raw, chunksize=3000))
        test_results = list(executor.map(extract_url_worker, X_test_raw, chunksize=3000))

    # Reconstruct text columns and numeric matrices
    train_domains = [r['domain'] if r else "" for r in train_results]
    train_paths = [r['path'] if r else "" for r in train_results]
    train_feats = [r['feats'] if r else {} for r in train_results]

    test_domains = [r['domain'] if r else "" for r in test_results]
    test_paths = [r['path'] if r else "" for r in test_results]
    test_feats = [r['feats'] if r else {} for r in test_results]

    X_train_lex_df = pd.DataFrame(train_feats).fillna(0)
    X_test_lex_df = pd.DataFrame(test_feats).fillna(0)
    print(f"✅ Extraction completed in {time.time() - t0:.1f}s")

    # --- 4. DUAL TF-IDF: DOMAIN ENGINE & PATH ENGINE ---
    print("\n🔤 Training Dual TF-IDF: Domain Engine (3,000 n-grams) + Path Engine (2,000 n-grams)...")
    t_tfidf = time.time()
    
    # Domain vectorizer: captures brand typosquatting and TLD anomalies
    vec_domain = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=3000, sublinear_tf=True)
    X_train_dom_tfidf = vec_domain.fit_transform(train_domains)
    X_test_dom_tfidf = vec_domain.transform(test_domains)

    # Path vectorizer: captures malicious directory tokens and attack scripts
    vec_path = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=2000, sublinear_tf=True)
    X_train_path_tfidf = vec_path.fit_transform(train_paths)
    X_test_path_tfidf = vec_path.transform(test_paths)
    print(f"✅ Dual TF-IDF compiled in {time.time() - t_tfidf:.1f}s")

    # --- 5. FUSE ALL MATRICES ---
    print("\n🔗 Fusing Domain Tokens + Path Tokens + Structural Features...")
    X_train_fused = hstack([X_train_dom_tfidf, X_train_path_tfidf, X_train_lex_df.values]).tocsr()
    X_test_fused = hstack([X_test_dom_tfidf, X_test_path_tfidf, X_test_lex_df.values]).tocsr()
    print(f"✅ Final Feature Vector Shape: {X_train_fused.shape} dimensions per URL")

    # --- 6. TRAIN LIGHTGBM CLASSIFIER ---
    print("\n🌲 Training LightGBM Gradient Boosted Decision Forest (300 Trees)...")
    t_train = time.time()
    
    lgbm = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.08,
        num_leaves=63,
        max_depth=12,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    lgbm.fit(X_train_fused, y_train)
    print(f"✅ LightGBM trained in {time.time() - t_train:.1f}s!")

    # --- 7. BENCHMARK & EVALUATION ---
    y_pred = lgbm.predict(X_test_fused)
    y_proba = lgbm.predict_proba(X_test_fused)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)

    print("\n" + "=" * 70)
    print(f"🎯 FINAL TEST ACCURACY : {acc * 100:.2f}%")
    print(f"📈 ROC-AUC SCORE       : {roc:.4f}")
    print("=" * 70)
    print("\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)'], digits=4))

    # --- 8. SAVE UNIFIED LIGHTWEIGHT ARTIFACTS ---
    artifacts = {
        'model': lgbm,
        'vec_domain': vec_domain,
        'vec_path': vec_path,
        'lexical_columns': list(X_train_lex_df.columns)
    }
    joblib.dump(artifacts, "phishing_hybrid_pipeline.pkl", compress=3)
    print("💾 Saved state-of-the-art LightGBM pipeline as 'phishing_hybrid_pipeline.pkl'!")

if __name__ == '__main__':
    main()
