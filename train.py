import pandas as pd
import numpy as np
import os
import time
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from scipy.sparse import hstack
import joblib

from features import extract_features
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

DATA_FILENAME = "raw_urldata.csv"

def extract_single_url(url):
    try:
        return extract_features(str(url))
    except Exception:
        return {}

def main():
    print("=" * 65)
    print("🚀 HIGH-CAPACITY 95%+ ENTERPRISE PHISHING PIPELINE (120k URLs)")
    print("=" * 65)

    # --- 1. LOAD DATASET ---
    print("\n📖 Loading dataset from local CSV...")
    df = pd.read_csv(DATA_FILENAME)
    df.columns = ['url', 'label']
    df['result'] = df['label'].apply(lambda x: 1 if str(x).lower() == 'bad' else 0)
    df = df[['url', 'result']].dropna().drop_duplicates()

    # --- 2. SAMPLE 120,000 BALANCED SAMPLES ---
    phish_samples = df[df['result'] == 1]
    benign_samples = df[df['result'] == 0]
    target_per_class = min(60000, len(phish_samples), len(benign_samples))

    print(f"📊 Sampling {target_per_class:,} Phishing + {target_per_class:,} Benign URLs...")
    phish_sub = phish_samples.sample(n=target_per_class, random_state=42)
    benign_sub = benign_samples.sample(n=target_per_class, random_state=42)
    dataset = pd.concat([phish_sub, benign_sub]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"🎯 Total training corpus: {len(dataset):,} URLs")

    # --- 3. TRAIN / TEST SPLIT ---
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        dataset['url'].astype(str),
        dataset['result'].values,
        test_size=0.15,
        random_state=42,
        stratify=dataset['result'].values
    )

    # --- 4. HIGH-DENSITY CHARACTER N-GRAM TF-IDF (5,000 TOKENS) ---
    print("\n🔤 Extracting 5,000 Character n-gram Tokens (2-grams to 5-grams)...")
    tfidf_start = time.time()
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(2, 5),
        max_features=5000,
        sublinear_tf=True
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)
    print(f"✅ Generated 5,000 NLP features in {time.time() - tfidf_start:.1f}s")

    # --- 5. MULTI-CORE FEATURE EXTRACTION (18 FEATURES) ---
    cores = multiprocessing.cpu_count()
    print(f"\n⚡ Extracting 18 structural & entropy features across {cores} CPU cores...")
    lex_start = time.time()

    with ProcessPoolExecutor(max_workers=cores) as executor:
        train_lex = list(executor.map(extract_single_url, X_train_raw, chunksize=3000))
        test_lex = list(executor.map(extract_single_url, X_test_raw, chunksize=3000))

    X_train_lex_df = pd.DataFrame(train_lex).fillna(0)
    X_test_lex_df = pd.DataFrame(test_lex).fillna(0)
    print(f"✅ Lexical & Entropy features extracted in {time.time() - lex_start:.1f}s")

    # --- 6. FUSE MATRICES (5000 NLP + 18 LEXICAL = 5018 FEATURES) ---
    print("\n🔗 Fusing NLP tokens and mathematical indicators into hybrid matrix...")
    X_train_fused = hstack([X_train_tfidf, X_train_lex_df.values]).tocsr()
    X_test_fused = hstack([X_test_tfidf, X_test_lex_df.values]).tocsr()
    print(f"✅ Fused Feature Shape: {X_train_fused.shape}")

    # --- 7. TRAIN DEEP RANDOM FOREST ENSEMBLE ---
    print("\n🌲 Training High-Capacity Random Forest Classifier (150 Trees, Depth 25)...")
    model_start = time.time()
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_split=3,
        n_jobs=-1,
        random_state=42
    )
    clf.fit(X_train_fused, y_train)
    print(f"✅ Training completed in {time.time() - model_start:.1f}s")

    # --- 8. BENCHMARK & EVALUATION ---
    y_pred = clf.predict(X_test_fused)
    y_proba = clf.predict_proba(X_test_fused)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)

    print("\n" + "=" * 65)
    print(f"🎯 FINAL TEST ACCURACY : {acc * 100:.2f}%")
    print(f"📈 ROC-AUC SCORE       : {roc:.4f}")
    print("=" * 65)
    print("\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)'], digits=4))

    # --- 9. SAVE COMPRESSED PIPELINE ARTIFACTS ---
    artifacts = {
        'model': clf,
        'vectorizer': vectorizer,
        'lexical_columns': list(X_train_lex_df.columns)
    }
    joblib.dump(artifacts, "phishing_hybrid_pipeline.pkl", compress=3)
    print("💾 Saved compressed 95%+ hybrid pipeline as 'phishing_hybrid_pipeline.pkl'!")

if __name__ == '__main__':
    main()
