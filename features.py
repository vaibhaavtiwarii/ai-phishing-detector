import urllib.parse
import re
import math
from collections import Counter

# High-risk keywords targeted by phishing campaigns
SUSPICIOUS_BRANDS = [
    'paypal', 'apple', 'netflix', 'amazon', 'google', 'microsoft',
    'bank', 'secure', 'login', 'verify', 'account', 'update', 'signin','meesho' , 'support' , 'flipkart' , 'paytm', 'hdfc', 'icici', 'axis', 'sbi', 'upi', 'phonepe', 'gpay', 'amazonpay', 'bhim', 'zelle',
]   

# Top TLDs mathematically overrepresented in active phishing databases
HIGH_RISK_TLDS = {
    'xyz', 'top', 'sbs', 'online', 'club', 'site', 'buzz', 'icu', 
    'monster', 'tk', 'ml', 'ga', 'cf', 'gq', 'fit', 'rest', 'work'
}

def calculate_shannon_entropy(text):
    """
    Calculates the Shannon Entropy of a string.
    High entropy indicates random character generation or obfuscation.
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def extract_features(url):
    """
    Extracts 18 advanced structural, mathematical, and heuristic features.
    """
    features = {}
    url_str = str(url).strip()
    
    # 1. Structural Lengths
    features['url_length'] = len(url_str)
    
    # 2. Character Frequencies
    features['count_dots'] = url_str.count('.')
    features['count_hyphens'] = url_str.count('-')
    features['count_at'] = url_str.count('@')
    features['count_question'] = url_str.count('?')
    features['count_equals'] = url_str.count('=')
    features['count_slash'] = url_str.count('/')
    features['count_digits'] = sum(c.isdigit() for c in url_str)
    
    # 3. Protocol Security
    features['is_https'] = 1 if url_str.startswith('https://') else 0

    # 4. Domain & Path Decomposition
    try:
        parsed = urllib.parse.urlparse(url_str if '://' in url_str else 'http://' + url_str)
        domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower().split('/')[0]
        path = parsed.path.lower()
    except Exception:
        domain = ""
        path = ""

    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['subdomain_count'] = max(0, domain.count('.') - 1)
    
    # 5. Shannon Entropy (Randomness calculation)
    features['domain_entropy'] = calculate_shannon_entropy(domain)
    features['url_entropy'] = calculate_shannon_entropy(url_str)

    # 6. Digit-to-Letter Ratio in Domain (DGA indicator)
    domain_digits = sum(c.isdigit() for c in domain)
    features['domain_digit_ratio'] = domain_digits / max(1, len(domain))

    # 7. Suspicious TLD Indicator
    domain_parts = domain.split('.')
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    features['is_suspicious_tld'] = 1 if tld in HIGH_RISK_TLDS else 0

    # 8. Brand Spoofing Check (Brand keyword inside subdomains or path, but NOT in main domain)
    root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    has_spoofed_brand = 0
    for brand in SUSPICIOUS_BRANDS:
        if (brand in domain or brand in path) and (brand not in root_domain):
            has_spoofed_brand = 1
            break
    features['has_brand_spoofing'] = has_spoofed_brand

    # 9. Raw IPv4 Address check
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['is_ip_domain'] = 1 if re.match(ip_pattern, domain) else 0

    return features

if __name__ == '__main__':
    sample = "https://limites-gold.my.canva.site/"
    print(f"Sample Extraction for {sample}:")
    for k, v in extract_features(sample).items():
        print(f"  {k:22s}: {v}")
