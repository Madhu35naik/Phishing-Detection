import re
import socket
import urllib3
import whois
import requests
import ipaddress
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import time
import warnings

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')
socket.setdefaulttimeout(3)  # Reduced from 5 to 3 seconds

# ===============================
# Helper Functions
# ===============================
def havingIP(url):
    try:
        ipaddress.ip_address(urlparse(url).netloc)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    try:
        path = urlparse(url).path.split('/')
        depth = len([segment for segment in path if segment])
        return depth
    except:
        return 0

def redirection(url):
    return 1 if url.rfind('//') > 7 else 0

def httpsDomain(url):
    domain = urlparse(url).netloc
    if re.search(r'http', domain, re.IGNORECASE):
        return 1
    return 0

def tinyURL(url):
    pattern = re.compile(
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
    )
    return 1 if re.search(pattern, url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def checkDnsRecord(url):
    """
    IMPROVED: Faster DNS check with better timeout handling
    """
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        
        if not domain:
            return 1
        
        # Quick socket resolution first (fastest method)
        try:
            socket.gethostbyname(domain)
            return 0  # DNS resolves = legitimate
        except socket.gaierror:
            pass  # Try DNS resolver as fallback
        
        # Fallback: DNS resolver
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=2)
            if answers and len(answers) > 0:
                return 0
        except:
            pass
        
        return 1  # No DNS record found
    except:
        return 1


def webTraffic(url):
    """
    IMPROVED: More realistic traffic check with better defaults
    """
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 1
        
        # Quick check: Well-known domains
        known_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                        'netflix', 'youtube', 'wikipedia', 'twitter', 'instagram']
        if any(known in domain for known in known_domains):
            return 0  # Popular domain = safe
        
        # Tranco ranking check
        tranco_url = f"https://tranco-list.eu/api/ranks/domain/{domain}"
        response = requests.get(tranco_url, timeout=3)
        
        if response.status_code == 200:
            data = response.json()
            if data and 'ranks' in data and len(data['ranks']) > 0:
                rank = data['ranks'][0]['rank']
                return 0 if rank < 500000 else 1
        
        # Unknown domain = slightly suspicious
        return 1
    except:
        return 0  # Network error = don't assume phishing

def domainAge(url):
    """
    IMPROVED: Better WHOIS handling with timeout and fallbacks
    """
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 0
        
        # Quick timeout for WHOIS
        info = whois.whois(domain, timeout=3)
        creation = info.creation_date
        
        if isinstance(creation, list):
            creation = min(creation) if creation else None
        
        if not creation:
            return 0  # No data = assume old
        
        if isinstance(creation, str):
            try:
                creation = datetime.strptime(creation, '%Y-%m-%d')
            except:
                return 0
        
        age_months = (datetime.now() - creation).days / 30.44
        return 1 if age_months < 6 else 0
    except:
        return 0  # WHOIS failed = assume legitimate (conservative)


def domainEnd(url):
    """
    IMPROVED: Better expiration check with timeout
    """
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 0
        
        info = whois.whois(domain, timeout=3)
        expiration = info.expiration_date
        
        if isinstance(expiration, list):
            expiration = min(expiration) if expiration else None
        
        if not expiration:
            return 0
        
        if isinstance(expiration, str):
            try:
                expiration = datetime.strptime(expiration, '%Y-%m-%d')
            except:
                return 0
        
        end_months = (expiration - datetime.now()).days / 30.44
        return 1 if end_months < 6 else 0
    except:
        return 0


def iframe(response):
    """
    IMPROVED: Better iframe detection
    """
    try:
        if not response or not hasattr(response, "text") or not response.text:
            return 0
        
        soup = BeautifulSoup(response.text, "html.parser")
        iframes = soup.find_all("iframe")
        
        # Multiple iframes are suspicious
        if len(iframes) > 3:
            return 1
        
        # Check for hidden/suspicious iframes
        for iframe_tag in iframes:
            style = str(iframe_tag.get('style', '')).lower()
            iframe_class = str(iframe_tag.get('class', '')).lower()
            
            if any(x in style for x in ['display:none', 'visibility:hidden', 'height:0', 'width:0']):
                return 1
            if any(x in iframe_class for x in ['hidden', 'invisible']):
                return 1
        
        return 0
    except:
        return 0


def mouseOver(response):
    """
    IMPROVED: Better mouse-over detection
    """
    try:
        if not response or not hasattr(response, "text") or not response.text:
            return 0
        
        text = response.text.lower()
        patterns = [
            r"onmouseover.*window\.status",
            r"onmouseover.*location\.href",
            r"onmouseover.*document\.location"
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 1
        
        return 0
    except:
        return 0


def rightClick(response):
    """
    IMPROVED: Better right-click detection
    """
    try:
        if not response or not hasattr(response, "text") or not response.text:
            return 0
        
        text = response.text.lower()
        patterns = [
            r"event\.button\s*==\s*2",
            r"oncontextmenu.*return false",
            r"oncontextmenu.*preventdefault",
            r"document\.oncontextmenu"
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 1
        
        return 0
    except:
        return 0


def webForward(response):
    """
    IMPROVED: Better redirect detection
    """
    try:
        if not response or not hasattr(response, "history"):
            return 0
        
        # 2+ redirects is suspicious
        return 1 if len(response.history) >= 2 else 0
    except:
        return 0


# ===============================
# Main Feature Extraction Function
# ===============================
def featureExtraction(url, label=None):
    """
    IMPROVED: Extracts 16 phishing detection features with better error handling.
    
    Args:
        url (str): The URL to analyze
        label (int, optional): Ground truth label (0=legitimate, 1=phishing)
    
    Returns:
        list: Feature values [16 features] or [16 features + label]
    """
    features = []
    
    try:
        # 1-8: Address Bar-based Features (ALWAYS WORK)
        features.append(havingIP(url))
        features.append(haveAtSign(url))
        features.append(getLength(url))
        features.append(getDepth(url))
        features.append(redirection(url))
        features.append(httpsDomain(url))
        features.append(tinyURL(url))
        features.append(prefixSuffix(url))

        # 9-12: Domain-based Features (MAY FAIL)
        features.append(checkDnsRecord(url))
        features.append(webTraffic(url))
        features.append(domainAge(url))
        features.append(domainEnd(url))

        # 13-16: HTML/JavaScript-based Features (OFTEN FAIL FOR PHISHING)
        response = None
        try:
            # More aggressive headers to avoid detection
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = requests.get(
                url, 
                timeout=4,  # Slightly longer timeout
                verify=False,
                headers=headers,
                allow_redirects=True,
                stream=False
            )
            
            print(f"✅ HTTP Success: {url} (Status: {response.status_code})")
            
        except requests.exceptions.Timeout:
            print(f"⏱️  Timeout: {url}")
        except requests.exceptions.ConnectionError:
            print(f"🔌 Connection Error: {url}")
        except requests.exceptions.TooManyRedirects:
            print(f"🔄 Too Many Redirects: {url}")
        except Exception as e:
            print(f"❌ HTTP Error: {url} - {str(e)[:50]}")
        
        features.append(iframe(response))
        features.append(mouseOver(response))
        features.append(rightClick(response))
        features.append(webForward(response))

        # Add label if provided
        if label is not None:
            features.append(label)

        return features

    except Exception as e:
        print(f"💥 Fatal Error: {url} - {e}")
        # Return default suspicious values on complete failure
        default_features = [1] * 16
        if label is not None:
            default_features.append(label)
        return default_features


# Feature names for reference (matches column order)
feature_names = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain',
    'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End',
    'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
]