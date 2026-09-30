import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from features import extract_features

df = pd.read_csv("data/urls.csv")
df = df.rename(columns={"URL": "url", "Label": "label"})
df["label"] = df["label"].map({"good": 0, "bad": 1})
df = df.dropna().drop_duplicates(subset="url")


df = df.sample(n=min(50_000, len(df)), random_state=42)

print("Extracting features...")
X = pd.DataFrame([extract_features(u) for u in df["url"]])
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

preds = model.predict(X_test)
print(classification_report(y_test, preds, target_names=["good", "bad"]))
print(confusion_matrix(y_test, preds))

joblib.dump({"model": model, "columns": list(X.columns)}, "model.joblib")
print("Saved model.joblib")