from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import urllib.parse
from scipy.sparse import hstack
from features import extract_features
from advisor import generate_security_advisory

app = FastAPI(
    title="AI Phishing Threat API",
    description="Low-latency inference endpoint for Browser Extensions and Email Gateways"
)

# Enable CORS so browser extensions can query the API locally without security blocks
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enterprise Verified Root Authority List
TOP_VERIFIED_ROOTS = {
    "facebook.com", "fb.com", "google.com", "google.co.in", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "amazon.in", "netflix.com",
    "github.com", "linkedin.com", "instagram.com", "twitter.com", "x.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "zoom.us", "paypal.com",
    "spotify.com", "adobe.com", "dropbox.com", "stackoverflow.com", "invertisuniversity.ac.in"
}

# Helper to extract root domain
def get_root_domain(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str if '://' in url_str else 'http://' + url_str)
        domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower().split('/')[0]
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            return ".".join(domain_parts[-2:])
        return domain
    except Exception:
        return ""

# Load pipeline artifacts
try:
    pipeline = joblib.load("phishing_hybrid_pipeline.pkl")
    model = pipeline['model']
    vec_domain = pipeline['vec_domain']
    vec_path = pipeline['vec_path']
    lexical_columns = pipeline['lexical_columns']
except Exception as e:
    raise RuntimeError(f"Failed to load model pipeline: {e}")

class ScanRequest(BaseModel):
    url: str

@app.get("/")
def health_check():
    return {"status": "online", "model": "Dual-Engine LightGBM", "accuracy": "96.27%"}

@app.post("/scan")
def scan_url(request: ScanRequest):
    url_str = request.url.strip()
    if not url_str:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    root_domain = get_root_domain(url_str)
    is_allowlisted = root_domain in TOP_VERIFIED_ROOTS
    
    # --- TIER 1: ALLOWLIST INTERCEPT ---
    if is_allowlisted:
        advisory = generate_security_advisory(
            url_str=url_str,
            is_phishing=False,
            risk_score=0.0,
            heuristics={},
            domain_str=root_domain,
            root_domain=root_domain,
            is_allowlisted=True
        )
        return {
            "url": url_str,
            "is_phishing": False,
            "risk_score": 0.0,
            "domain": root_domain,
            "tier_used": "Enterprise Allowlist",
            "advisory": advisory
        }
    
    # --- TIER 2: MACHINE LEARNING INFERENCE ---
    try:
        raw_lexical, domain_str, path_str = extract_features(url_str)
        domain_tfidf = vec_domain.transform([domain_str])
        path_tfidf = vec_path.transform([path_str])
        lexical_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)
        
        fused = hstack([domain_tfidf, path_tfidf, lexical_df.values]).tocsr()
        prediction = int(model.predict(fused)[0])
        risk_score = float(model.predict_proba(fused)[0][1] * 100)
        is_phish = bool(prediction == 1 or risk_score > 50)

        # Generate Contextual Security Checklist
        advisory = generate_security_advisory(
            url_str=url_str,
            is_phishing=is_phish,
            risk_score=risk_score,
            heuristics=raw_lexical,
            domain_str=domain_str,
            root_domain=root_domain,
            is_allowlisted=False
        )
        
        return {
            "url": url_str,
            "is_phishing": is_phish,
            "risk_score": round(risk_score, 2),
            "domain": domain_str,
            "tier_used": "LightGBM ML Classifier",
            "advisory": advisory
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {e}")

# --- 3. EXECUTION WRAPPER ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)