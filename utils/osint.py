import socket
import ssl
import requests
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url: str) -> str:
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        # Remove 'www.' if present to keep queries clean
        if domain.startswith("www."):
            domain = domain[3:]
        return domain
    except Exception:
        return ""

def get_domain_age_days(domain: str) -> int:
    """
    Uses the official, open-source RDAP standard API to fetch registration dates.
    This bypasses local firewall blocks entirely.
    """
    if not domain or domain in ["localhost", "127.0.0.1"]:
        return 0
    
    try:
        # We query the open RDAP service (modern, reliable replacement for WHOIS)
        rdap_url = f"https://rdap.org/domain/{domain}"
        response = requests.get(rdap_url, timeout=4)
        
        if response.status_code == 200:
            data = response.json()
            events = data.get("events", [])
            
            for event in events:
                # Look for registration or creation timeline events
                if event.get("eventAction") in ["registration", "creation"]:
                    event_date_str = event.get("eventDate")
                    # Date looks like: '1997-09-15T04:00:00Z'
                    # We cut the string to grab just the YYYY-MM-DD portion
                    clean_date_str = event_date_str.split("T")[0]
                    creation_date = datetime.strptime(clean_date_str, "%Y-%m-%d")
                    
                    age_days = (datetime.now() - creation_date).days
                    return max(0, age_days)
                    
        # If the domain is not found in the registry (likely a fake/phishing link)
        return 14
    except Exception:
        # Fallback if network cuts out
        return 14

def analyze_ssl_certificate(domain: str) -> dict:
    result = {"ssl_active": False, "issuer": "Unknown", "days_to_expiry": 0}
    if not domain:
        return result

    context = ssl.create_default_context()
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result["ssl_active"] = True
                    issuer_info = cert.get('issuer', ())
                    for item in issuer_info:
                        for sub_item in item:
                            if sub_item[0] == 'organizationName':
                                result["issuer"] = sub_item[1]
                    
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry_date - datetime.now()).days
                        result["days_to_expiry"] = max(0, days_left)
        return result
    except Exception:
        return result