import urllib.parse
import re
import math
from collections import Counter

SUSPICIOUS_BRANDS = [
    'paypal', 'apple', 'netflix', 'amazon', 'google', 'microsoft',
    'bank', 'secure', 'login', 'verify', 'account', 'update', 'signin', 'support'
]

HIGH_RISK_TLDS = {
    'xyz', 'top', 'sbs', 'online', 'club', 'site', 'buzz', 'icu', 
    'monster', 'tk', 'ml', 'ga', 'cf', 'gq', 'fit', 'rest', 'work'
}

def calculate_shannon_entropy(text):
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
    Extracts numerical features and decomposes the URL into clean domain and path components.
    """
    features = {}
    url_str = str(url).strip()
    
    # 1. Structural lengths
    features['url_length'] = len(url_str)
    
    # 2. Character counts
    features['count_dots'] = url_str.count('.')
    features['count_hyphens'] = url_str.count('-')
    features['count_at'] = url_str.count('@')
    features['count_question'] = url_str.count('?')
    features['count_equals'] = url_str.count('=')
    features['count_slash'] = url_str.count('/')
    features['count_digits'] = sum(c.isdigit() for c in url_str)
    features['count_hex'] = len(re.findall(r'%[0-9a-fA-F]{2}', url_str))
    
    # 3. Protocol security
    features['is_https'] = 1 if url_str.startswith('https://') else 0

    # 4. Domain & Path decomposition
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
    
    # 5. Shannon Entropy
    features['domain_entropy'] = calculate_shannon_entropy(domain)
    features['url_entropy'] = calculate_shannon_entropy(url_str)

    # 6. Linguistic indicators (DGA detection)
    vowels = sum(c in 'aeiou' for c in domain)
    consonants = sum(c.isalpha() and c not in 'aeiou' for c in domain)
    features['domain_vowel_ratio'] = vowels / max(1, (vowels + consonants))
    features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / max(1, len(domain))

    # 7. Suspicious TLD & Brand Spoofing
    domain_parts = domain.split('.')
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    features['is_suspicious_tld'] = 1 if tld in HIGH_RISK_TLDS else 0

    root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    features['has_brand_spoofing'] = 1 if any(
        (b in domain or b in path) and (b not in root_domain) for b in SUSPICIOUS_BRANDS
    ) else 0

    # 8. Raw IPv4 domain check
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['is_ip_domain'] = 1 if re.match(ip_pattern, domain) else 0

    return features, domain, path

if __name__ == '__main__':
    feats, d, p = extract_features("https://limites-gold.my.canva.site/update")
    print("Domain:", d)
    print("Path:", p)
    print("Features extracted:", len(feats))
