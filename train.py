import pandas as pd
import numpy as np
import urllib.request
import os
from features import extract_features
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import warnings

# Suppress warnings for a cleaner output
warnings.filterwarnings("ignore", category=UserWarning)

# --- 1. DATASET INFORMATION ---
DATA_FILENAME = "raw_urldata.csv"
DATAURL = "https://raw.githubusercontent.com/somanivihar1498/Detect-Malicious-URL-Using-logistic-regression/master/urldata.csv"

def download_data():
    if not os.path.exists(DATA_FILENAME):
        print("📥 Downloading raw URL dataset...")
        try:
            urllib.request.urlretrieve(DATAURL, DATA_FILENAME)
            print("✅ Download complete!")
        except Exception as e:
            print(f"❌ Error downloading file: {e}")
            return False
    else:
        print("📦 Raw URL dataset already exists locally.")
    return True

if download_data():
    # --- 2. LOAD AND PARSE DATA ---
    print("📖 Loading and parsing raw URLs...")
    df = pd.read_csv(DATA_FILENAME)
    
    # Rename columns to a standard format ('url', 'label')
    df.columns = ['url', 'label']

    # Convert text labels 'good' and 'bad' to 0 and 1
    df['result'] = df['label'].apply(lambda x: 1 if str(x).lower() == 'bad' else 0)
    
    # Clean and keep only the necessary columns
    df = df[['url', 'result']].dropna().drop_duplicates()

    # --- 3. CREATE A BALANCED SUBSAMPLE ---
    phish_samples = df[df['result'] == 1]
    benign_samples = df[df['result'] == 0]

    print(f"Total available Phishing URLs in dataset: {len(phish_samples)}")
    print(f"Total available Benign URLs in dataset: {len(benign_samples)}")

    # Create a balanced set for training to prevent bias
    n_samples = min(len(phish_samples), len(benign_samples), 10000) # Cap at 10k for speed
    phish_subset = phish_samples.sample(n=n_samples, random_state=42)
    benign_subset = benign_samples.sample(n=n_samples, random_state=42)
    
    subset_df = pd.concat([phish_subset, benign_subset]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"📊 Processing a balanced set of {len(subset_df)} URLs...")

    # --- 4. EXTRACT FEATURES FROM RAW URLS ---
    print("⚡ Extracting lexical features from URLs (this may take a minute)...")
    feature_list = subset_df['url'].apply(extract_features)
    features_df = pd.DataFrame(feature_list.tolist())
    
    # Combine extracted features with the labels
    processed_df = pd.concat([features_df, subset_df['result']], axis=1)
    processed_df = processed_df.dropna()
    print("✅ Feature extraction complete!")

    # --- 5. TRAIN THE REAL-WORLD MODEL ---
    X = processed_df.drop(columns=['result'])
    y = processed_df['result']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("\n🌲 Training the Real-World Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=150, min_samples_split=5, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("✅ Training complete!")

    # --- 6. EVALUATE THE NEW MODEL ---
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n🎯 Real-World Model Accuracy: {accuracy * 100:.2f}%")
    print("\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)']))

    # --- 7. SAVE THE NEW, SMARTER MODEL ---
    joblib.dump(model, "phishing_model_real.pkl")
    print("\n💾 Saved new real-world model as 'phishing_model_real.pkl'!")
