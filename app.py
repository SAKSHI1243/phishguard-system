from typing import TYPE_CHECKING

import streamlit as st
import requests

# 1. Page Configuration & Title Styling
st.set_page_config(
    page_title="PhishGuard Link Defuser",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PhishGuard Engine")
st.markdown("### Real-Time Session-Hijacking Protection & Link Defuser Dashboard")
st.write("Drop any suspicious link below to safely dissect its structural properties, domain age, and ML probability metrics before clicking.")

st.markdown("---")

# 2. User Input Section
target_url = st.text_input("🔗 Enter URL to inspect safely:", placeholder="https://example.com")

if st.button("Run Threat Analysis Matrix", use_container_width=True):
    if not target_url.strip():
        st.warning("Please provide a valid URL string first.")
    else:
        with st.spinner("Analyzing threat vectors... Intercepting tokens..."):
            try:
                # Send the input URL payload to your live FastAPI backend endpoint
                backend_endpoint = "http://127.0.0.1:8000/api/v1/analyze"
                payload = {"url": target_url.strip()}
                
                response = requests.post(backend_endpoint, json=payload, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    score = data["threat_score"]
                    verdict = data["verdict"]
                    details = data["details"]
                    
                    # 3. Dynamic Visual Card Generation based on Threat Score
                    if score >= 75.0:
                        st.error(f"### 🛑 {verdict}")
                    elif score >= 45.0:
                        st.warning(f"### ⚠️ {verdict}")
                    else:
                        st.success(f"### ✅ {verdict}")
                        
                    # 4. Metric Columns Layout
                    st.markdown("#### 📊 Core Vector Breakdown")
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric(
                            label="Threat Index Score", 
                            value=f"{score} / 100", 
                            delta="- HIGH RISK" if score >= 45 else "+ SAFE",
                            delta_color="inverse"
                        )
                    with col2:
                        st.metric(
                            label="Domain Registry Age", 
                            value=f"{details['domain_age_days']} Days" if details['domain_age_days'] != 14 else "Suspicious/New"
                        )
                    with col3:
                        st.metric(
                            label="ML Classifier Prob.", 
                            value=f"{round(details['ml_prediction_prob'] * 100, 1)}%"
                        )
                        
                    st.markdown("---")
                    
                    # 5. Technical Signals Inspector
                    st.markdown("#### 🔍 Underlying Deep-Inspection Logs")
                    
                    log_col1, log_col2 = st.columns(2)
                    with log_col1:
                        st.markdown(f"**Cleaned Domain:** `{details['domain_name']}`")
                        st.markdown(f"**SSL Encryption Active:** `{details['ssl_valid']}`")
                        st.markdown(f"**SSL Certificate Issuer:** `{details['ssl_issuer']}`")
                    with log_col2:
                        st.markdown(f"**Credential Password Inputs:** `{details['password_inputs_found']}`")
                        st.markdown(f"**Visual Brand Spoofing Detected:** `{details['visual_spoofing_detected']}`")
                        
                else:
                    st.error("Backend Engine returned an operational error code. Ensure your FastAPI data parsing schemas match.")
                    
            except requests.exceptions.ConnectionError:
                st.error("❌ Connection Refused! Make sure your FastAPI backend server is currently running on `http://127.0.0.1:8000` via your other terminal window.")