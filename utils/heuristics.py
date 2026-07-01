import requests
from bs4 import BeautifulSoup

def analyze_dom_heuristics(url: str, domain: str) -> dict:
    """
    Safely downloads a webpage's raw HTML and scans structural text 
    for credential harvesters and brand spoofing traits.
    """
    flags = {
        "password_fields_count": 0,
        "contains_sensitive_keywords": False,
        "visual_brand_spoofing": False,
        "matched_brand": "None"
    }
    
    # Target brand list to detect visual spoofing vectors
    target_brands = ["amazon", "flipkart", "instagram", "facebook", "hdfc", "sbi", "phonepe", "paypal", "netflix"]
    sensitive_keywords = ["login", "verify", "otp", "password", "secure", "account", "update", "kyc"]
    
    try:
        # Strict 4-second timeout to prevent API hanging
        # Custom header makes our background fetch look like a normal web browser
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, timeout=4, headers=headers)
        
        if response.status_code != 200:
            return flags # Return clean flags if the page is dead/unreachable
            
        soup = BeautifulSoup(response.text, "html.parser")
        
        # 1. Check for Password Input Fields in DOM Structure
        password_inputs = soup.find_all("input", {"type": "password"})
        flags["password_fields_count"] = len(password_inputs)
        
        # 2. Extract clean, lower-case text from the entire page
        page_text = soup.get_text().lower()
        
        # 3. Check for high-risk security keywords
        keyword_matches = [word for word in sensitive_keywords if word in page_text]
        if len(keyword_matches) >= 2 or flags["password_fields_count"] > 0:
            flags["contains_sensitive_keywords"] = True
            
        # 4. The Visual Spoofing Logic:
        # If the text body mentions "amazon", but "amazon" is NOT in the actual domain name string, 
        # that is a textbook visual phishing trap.
        for brand in target_brands:
            if brand in page_text and brand not in domain:
                flags["visual_brand_spoofing"] = True
                flags["matched_brand"] = brand.capitalize()
                break # Stop scanning once a brand match is confirmed
                
        return flags
        
    except Exception:
        # If the page structure is completely broken or refuses connection, 
        # return empty flags gracefully to let other layers handle the score.
        return flags