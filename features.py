import urllib.parse
import re

def extract_features(url):
    """
    Analyzes a URL string and extracts numerical features for Machine Learning.
    Returns a dictionary of features.
    """
    features = {}
    
    # 1. URL Length (Phishing URLs are often artificially long)
    features['url_length'] = len(url)
    
    # 2. Count of specific characters often abused in phishing URLs
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')  # Often used to mask the real domain
    features['count_question'] = url.count('?')
    features['count_equals'] = url.count('=')
    features['count_slash'] = url.count('/')
    
    # 3. Check if the URL uses HTTPS (1 for True, 0 for False)
    features['is_https'] = 1 if url.startswith('https://') else 0
    
    # 4. Check for presence of IP Address in place of a domain name
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    has_ip = re.search(ip_pattern, url)
    features['has_ip'] = 1 if has_ip else 0
    
    # 5. Domain-level features (parsing the domain name out of the URL)
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        features['domain_length'] = len(domain)
        features['domain_dots'] = domain.count('.')
    except Exception:
        features['domain_length'] = 0
        features['domain_dots'] = 0
        
    return features

if __name__ == "__main__":
    safe_url = "https://www.google.com"
    suspicious_url = "http://signin.paypal-security-update.com/login.php?id=102"
    
    print("Safe URL Features:")
    print(extract_features(safe_url))
    print("\nSuspicious URL Features:")
    print(extract_features(suspicious_url))
