import urllib.parse
import re
from math import log

def extract_features(url):
    """
    Analyzes a URL string and extracts a richer set of numerical features for Machine Learning.
    This version includes more sophisticated domain analysis.
    """
    features = {}

    # --- Basic Length & Character Counts ---
    features['url_length'] = len(url)
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_question'] = url.count('?')
    features['count_equals'] = url.count('=')
    features['count_slash'] = url.count('/')
    features['count_www'] = url.lower().count('www')
    
    # --- Protocol Analysis ---
    features['is_https'] = 1 if url.startswith('https://') else 0

    # --- Domain & Path Analysis ---
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
        path = parsed_url.path
    except Exception:
        domain = ""
        path = ""

    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    
    # --- NEW: Advanced Domain Features ---
    # Does the domain contain common sensitive keywords?
    sensitive_keywords = ['login', 'secure', 'account', 'update', 'verify', 'paypal', 'admin', 'signin']
    features['has_sensitive_keywords'] = 1 if any(keyword in domain.lower() for keyword in sensitive_keywords) else 0

    # NEW: Is a Top-Level Domain (TLD) present?
    domain_parts = domain.split('.')
    features['has_tld'] = 1 if len(domain_parts) > 1 and len(domain_parts[-1]) > 1 else 0
    
    # NEW: Count of subdomains
    features['subdomain_count'] = domain.count('.')

    # NEW: Is an IP address used as the domain?
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['is_ip_domain'] = 1 if re.match(ip_pattern, domain) else 0

    return features

# --- QUICK TEST ---
if __name__ == "__main__":
    test_url = "https://limites-gold.my.canva.site/"
    print(f"Features for: {test_url}")
    print(extract_features(test_url))
