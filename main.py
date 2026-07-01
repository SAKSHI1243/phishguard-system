import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import LinkAnalysisRequest, LinkAnalysisResponse
from contextlib import asynccontextmanager

# Import your Day 2 and Day 3 custom scanning layers
from utils.osint import extract_domain, get_domain_age_days, analyze_ssl_certificate
from utils.heuristics import analyze_dom_heuristics

# Global handles to initialize our model once
model = None
vectorizer = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Asynchronously loads weights into RAM on backend initialization
    to keep API scoring instant.
    """
    global model, vectorizer
    try:
        model = joblib.load("models/phishing_classifier.joblib")
        vectorizer = joblib.load("models/vectorizer.joblib")
        print("🔥 PhishGuard Micro-Token ML Weights Loaded Successfully!")
    except Exception as e:
        print(f"⚠️ Initialization Error: {e}")
    yield

app = FastAPI(
    title="PhishGuard Engine",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def calculate_threat_score(url: str, domain: str, age_days: int, visual_spoofing: bool, ml_prob: float) -> tuple[float, str]:
    """
    Enhanced Multi-Layered Threat Matrix.
    Catches text patterns even if the ML model returns 0%.
    """
    # 1. Base Score from Domain Age (40% Weight)
    # New/Suspicious domains get maximum age penalty
    if age_days < 30:
        age_score = 100.0
    elif age_days < 180:
        age_score = 50.0
    else:
        age_score = 0.0

    # 2. Visual Heuristic/DOM Spoofing Score (30% Weight)
    heuristic_score = 100.0 if visual_spoofing else 0.0

    # 3. Machine Learning Score (30% Weight)
    ml_score = ml_prob * 100.0

    # --- ADVANCED CYBERSECURITY OVERRIDE RULES (The Safety Net) ---
    # Rule A: Check if the domain text itself contains heavy phishing keywords
    high_risk_keywords = ["login", "secure", "instagram", "facebook", "amazon", "verify", "update"]
    keyword_matches = [word for word in high_risk_keywords if word in domain.lower()]
    
    # If the domain is brand new, has no SSL, AND contains phishing keywords,
    # we force an absolute minimum high risk baseline.
    keyword_anomaly = len(keyword_matches) >= 2
    
    # Calculate initial weighted matrix math
    final_score = (0.40 * age_score) + (0.30 * heuristic_score) + (0.30 * ml_score)
    
    # Apply overriding risk inflation if structural patterns are obviously malicious
    if keyword_anomaly and age_days < 30:
        final_score = max(final_score, 85.0)  # Force a Critical Threat score
    elif keyword_anomaly:
        final_score = max(final_score, 60.0)  # Force a Suspicious score

    final_score = round(final_score, 2)

    # Determine Final Verdict
    if final_score >= 75.0:
        verdict = "CRITICAL: Phishing/Token-Theft Attack Pattern Confirmed!"
    elif final_score >= 45.0:
        verdict = "SUSPICIOUS: Elevated Risk Indicators Flagged."
    else:
        verdict = "SAFE: No Significant Phishing Signals Detected."

    return final_score, verdict

@app.post("/api/v1/analyze", response_model=LinkAnalysisResponse)
async def analyze_link(payload: LinkAnalysisRequest):
    input_url = payload.url.strip()
    if not input_url:
        raise HTTPException(status_code=400, detail="URL input field empty.")
        
    domain = extract_domain(input_url)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL format.")
        
    # Gather background heuristics & meta-signals
    age_days = get_domain_age_days(domain)
    ssl_details = analyze_ssl_certificate(domain)
    html_heuristics = analyze_dom_heuristics(input_url, domain)
    
    # ML Pipeline Execution
    ml_probability = 0.0
    if model is not None and vectorizer is not None:
        try:
            # Match current text string with saved sub-token space
            transformed_features = vectorizer.transform([input_url])
            probabilities = model.predict_proba(transformed_features)[0]
            ml_probability = float(probabilities[1]) # Index 1 tracking the phishing index probability
        except Exception as err:
            print(f"ML Pipeline Failure: {err}")
            ml_probability = 0.50

    # Update this call to pass the 'input_url' and 'domain' variables as well!
    threat_score, verdict = calculate_threat_score(
        url=input_url,
        domain=domain,
        age_days=age_days,
        visual_spoofing=html_heuristics["visual_brand_spoofing"],
        ml_prob=ml_probability
    )
    return LinkAnalysisResponse(
        url=input_url,
        status="Success",
        threat_score=threat_score,
        verdict=verdict,
        details={
            "domain_name": domain,
            "domain_age_days": age_days,
            "ssl_valid": ssl_details["ssl_active"],
            "ssl_issuer": ssl_details["issuer"],
            "password_inputs_found": html_heuristics["password_fields_count"],
            "visual_spoofing_detected": html_heuristics["visual_brand_spoofing"],
            "ml_prediction_prob": round(ml_probability, 4)
        }
    )