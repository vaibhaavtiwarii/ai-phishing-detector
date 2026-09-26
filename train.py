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
    """Fast lexical feature extraction."""
    try:
        return extract_features(str(url))
    except Exception:
        return {}

def main():
    print("=" * 65)
    print("🛡️ STATE-OF-THE-ART HYBRID NLP + LEXICAL PHISHING ENGINE")
    print("=" * 65)

    # --- 1. LOAD DATASET ---
    print("\n📖 Loading dataset from local CSV...")
    df = pd.read_csv(DATA_FILENAME)
    df.columns = ['url', 'label']
    df['result'] = df['label'].apply(lambda x: 1 if str(x).lower() == 'bad' else 0)
    df = df[['url', 'result']].dropna().drop_duplicates()

    # Balanced 30,000 URL subset (15k Phishing, 15k Benign)
    # We use 30,000 samples to keep training extremely fast while maximizing accuracy!
    phish_samples = df[df['result'] == 1]
    benign_samples = df[df['result'] == 0]
    target_per_class = min(15000, len(phish_samples), len(benign_samples))

    phish_sub = phish_samples.sample(n=target_per_class, random_state=42)
    benign_sub = benign_samples.sample(n=target_per_class, random_state=42)
    dataset = pd.concat([phish_sub, benign_sub]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"📊 Training corpus: {len(dataset):,} balanced URLs")


    # --- 2. TRAIN / TEST SPLIT ---
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        dataset['url'].astype(str),
        dataset['result'].values,
        test_size=0.2,
        random_state=42,
        stratify=dataset['result'].values
    )

    # --- 3. NLP CHARACTER N-GRAM TF-IDF ---
    print("\n🔤 Computing Character-level TF-IDF (3-grams to 5-grams)...")
    tfidf_start = time.time()
    
    # Extract structural sub-word tokens
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(3, 5),
        max_features=2500,  # Focus on the top 2,500 most decisive URL text tokens
        sublinear_tf=True
    )

    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)
    print(f"✅ Generated 2,500 NLP n-gram features in {time.time() - tfidf_start:.1f}s")

    # --- 4. PARALLEL LEXICAL FEATURE EXTRACTION ---
    cores = multiprocessing.cpu_count()
    print(f"\n⚡ Extracting 15 structural lexical features across {cores} CPU cores...")
    lex_start = time.time()

    with ProcessPoolExecutor(max_workers=cores) as executor:
        train_lex = list(executor.map(extract_single_url, X_train_raw, chunksize=2000))
        test_lex = list(executor.map(extract_single_url, X_test_raw, chunksize=2000))

    X_train_lex_df = pd.DataFrame(train_lex).fillna(0)
    X_test_lex_df = pd.DataFrame(test_lex).fillna(0)
    print(f"✅ Lexical features extracted in {time.time() - lex_start:.1f}s")

    # --- 5. FUSE MATRICES (NLP 2500 + LEXICAL 15 = 2515 FEATURES) ---
    print("\n🔗 Fusing NLP tokens and structural indicators into hybrid matrix...")
    X_train_fused = hstack([X_train_tfidf, X_train_lex_df.values]).tocsr()
    X_test_fused = hstack([X_test_tfidf, X_test_lex_df.values]).tocsr()
    print(f"✅ Fused Feature Shape: {X_train_fused.shape} total dimensions per URL")

    # --- 6. TRAIN NON-LINEAR CLASSIFIER (Random Forest) ---
    print("\n🌲 Training High-Capacity Random Forest Classifier (100 Trees)...")
    model_start = time.time()
    
    # RandomForest handles unscaled features beautifully and excels at non-linear boundaries
    clf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    clf.fit(X_train_fused, y_train)
    print(f"✅ Training completed in {time.time() - model_start:.1f}s")

    # --- 7. BENCHMARK & EVALUATION ---
    y_pred = clf.predict(X_test_fused)
    y_proba = clf.predict_proba(X_test_fused)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)

    print("\n" + "=" * 65)
    print(f"🎯 HYBRID MODEL TEST ACCURACY : {acc * 100:.2f}%")
    print(f"📈 ROC-AUC SCORE             : {roc:.4f}")
    print("=" * 65)
    print("\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)'], digits=4))

      # --- 8. SAVE PIPELINE ARTIFACTS ---
    artifacts = {
        'model': clf,
        'vectorizer': vectorizer,
        'lexical_columns': list(X_train_lex_df.columns)
    }
    # compress=3 uses zlib compression to shrink the file by up to 90%!
    joblib.dump(artifacts, "phishing_hybrid_pipeline.pkl", compress=3)

    print("💾 Saved hybrid pipeline artifacts as 'phishing_hybrid_pipeline.pkl'!")
