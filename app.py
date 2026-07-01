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

# FIXED: Pointing to the exact v1 API route found in your docs
BACKEND_URL = "https://phishguard-systems.onrender.com/api/v1/analyze"

# 2. User Input Section
target_url = st.text_input("🔗 Enter URL to inspect safely:", placeholder="https://example.com")

if st.button("Run Threat Analysis Matrix", use_container_width=True):
    if not target_url.strip():
        st.warning("Please provide a valid URL string first.")
    else:
        with st.spinner("Analyzing threat vectors..."):
            try:
                # The payload schema {"url": "..."} matches perfectly
                payload = {"url": target_url.strip()}
                
                response = requests.post(BACKEND_URL, json=payload, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extracting keys guaranteed by your Response Schema
                    score = data.get("threat_score", 0)
                    verdict = data.get("verdict", "Unknown")
                    status = data.get("status", "Processed")
                    details = data.get("details", {})
                    
                    # 3. Dynamic Visual Card Generation based on Threat Score
                    if score >= 75.0:
                        st.error(f"### 🛑 {verdict} ({status.upper()})")
                    elif score >= 45.0:
                        st.warning(f"### ⚠️ {verdict} ({status.upper()})")
                    else:
                        st.success(f"### ✅ {verdict} ({status.upper()})")
                        
                    # 4. Metric Columns Layout
                    st.markdown("#### 📊 Core Vector Breakdown")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.metric(
                            label="Threat Index Score", 
                            value=f"{score} / 100", 
                            delta="- HIGH RISK" if score >= 45 else "+ SAFE",
                            delta_color="inverse"
                        )
                    with col2:
                        st.metric(
                            label="Analysis Status", 
                            value=str(status).capitalize()
                        )
                        
                    # 5. Technical Signals Inspector (Safely parsing details dictionary)
                    if details:
                        st.markdown("---")
                        st.markdown("#### 🔍 Underlying Deep-Inspection Metrics")
                        st.json(details) # Outputs the key-value dictionary attributes cleanly dynamically
                        
                elif response.status_code == 422:
                    st.error("❌ Schema Validation Error (422). The structure sent did not pass backend verification checks.")
                else:
                    st.error(f"Backend Engine returned an operational error code ({response.status_code}).")
                    
            except requests.exceptions.Timeout:
                st.error("⏱️ **Connection Timeout!** Your free Render backend instance is spinning up from cold-sleep. Give it a brief moment and try scanning again!")
                
            except requests.exceptions.ConnectionError:
                st.error(f"❌ **Connection Refused!** Streamlit frontend was unable to hit the cloud API endpoint at `{BACKEND_URL}`.")