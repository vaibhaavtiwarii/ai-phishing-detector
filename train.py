import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib  # To save our trained model file!

# --- 1. LOAD THE DATA ---
DATA_FILENAME = "phishing_dataset.csv"
print("📖 Loading dataset...")
df = pd.read_csv(DATA_FILENAME)

# --- 2. SEPARATE FEATURES AND TARGETS ---
X = df.drop(columns=['Result'])
y = df['Result']

# --- 3. SPLIT DATA INTO TRAIN (80%) AND TEST (20%) ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("📊 Data Split Complete!")
print(f"Training samples: {X_train.shape[0]}")
print(f"Testing samples: {X_test.shape[0]}")

# --- 4. TRAIN THE RANDOM FOREST MODEL ---
print("\n🌲 Training the Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("✅ Training complete!")

# --- 5. EVALUATE THE MODEL ---
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Model Accuracy: {accuracy * 100:.2f}%")

print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Phishing (-1)', 'Legitimate (1)']))

# --- 6. SAVE THE MODEL FOR THE DASHBOARD ---
joblib.dump(model, 'phishing_model.pkl')
print("\n💾 Model saved successfully as 'phishing_model.pkl'!")
