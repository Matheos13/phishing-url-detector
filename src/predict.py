import joblib
import pandas as pd
from pathlib import Path
from features import extract_features

MODEL_PATH = Path(__file__).resolve().parent.parent / "model.joblib"
bundle = joblib.load(MODEL_PATH)

def check_url(url: str) -> dict:
    feats = pd.DataFrame([extract_features(url)])[bundle["columns"]]
    prob = float(bundle["model"].predict_proba(feats)[0][1])
    return {
        "url": url,
        "phishing_probability": round(prob, 3),
        "verdict": "Likely phishing" if prob >= 0.5 else "Likely safe",
        "features": feats.iloc[0].to_dict(),
    }

if __name__ == "__main__":
    for u in ["https://www.google.com", "http://paypal.secure-login.verify-account.xyz/update"]:
        print(check_url(u)["verdict"], "-", u)