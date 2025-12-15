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
socket.setdefaulttimeout(5)

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
    """Check DNS record availability with retry mechanism."""
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        
        if not domain:
            return 1  # Invalid or empty domain name
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA']

        # Try DNS resolution
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=2)
                if answers and len(answers) > 0:
                    return 0  # Found valid DNS record
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception:
                continue

        # Fallback: socket resolution with retry
        for attempt in range(2):
            try:
                socket.gethostbyname(domain)
                return 0  # Resolves = legitimate
            except Exception:
                if attempt == 0:
                    time.sleep(0.5)  # Brief pause before retry
                else:
                    return 1  # Still fails = suspicious
        
        return 1  # Default to suspicious if all methods fail
    except:
        return 1


def webTraffic(url):
    """Check web traffic using Tranco ranking with improved thresholds."""
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 1
        
        tranco_url = f"https://tranco-list.eu/api/ranks/domain/{domain}"
        response = requests.get(tranco_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data and 'ranks' in data and len(data['ranks']) > 0:
                rank = data['ranks'][0]['rank']
                if rank < 100000:
                    return 0  # High traffic = legitimate
                elif rank < 500000:
                    return 0  # Medium traffic = still okay
                else:
                    return 1  # Very low traffic = suspicious
        
        return 0  # Not ranked ≠ phishing (conservative approach)
    except:
        return 0  # Fail open for network errors

def domainAge(url):
    """Calculate domain age with improved error handling."""
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 0
        
        info = whois.whois(domain)
        creation = info.creation_date
        
        if isinstance(creation, list):
            creation = min(creation) if creation else None
        
        if not creation:
            return 0  # Assume old/stable if no creation date
        
        if isinstance(creation, str):
            try:
                creation = datetime.strptime(creation, '%Y-%m-%d')
            except:
                return 0
        
        age_months = (datetime.now() - creation).days / 30.44
        return 1 if age_months < 6 else 0
    except:
        return 0  # Assume legitimate if WHOIS fails


def domainEnd(url):
    """Calculate domain expiration with improved error handling."""
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 0
        
        info = whois.whois(domain)
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
        return 0  # Assume legitimate on WHOIS failure


def iframe(response):
    """Detect suspicious iframe usage."""
    try:
        if not response or not hasattr(response, "text"):
            return 0
        
        soup = BeautifulSoup(response.text, "html.parser")
        iframes = soup.find_all("iframe")
        
        # Multiple iframes or hidden iframes are suspicious
        if len(iframes) > 3:
            return 1
        
        # Check for hidden iframes
        for iframe_tag in iframes:
            style = iframe_tag.get('style', '')
            if 'display:none' in style or 'visibility:hidden' in style:
                return 1
        
        return 0
    except:
        return 0


def mouseOver(response):
    """Detect mouse-over status bar manipulation."""
    try:
        if not response or not hasattr(response, "text"):
            return 0
        return 1 if re.search(r"onmouseover.*window\.status", response.text, re.IGNORECASE) else 0
    except:
        return 0


def rightClick(response):
    """Detect right-click disabling."""
    try:
        if not response or not hasattr(response, "text"):
            return 0
        pattern = r"event\.button\s*==\s*2|oncontextmenu.*return false"
        return 1 if re.search(pattern, response.text, re.IGNORECASE) else 0
    except:
        return 0


def webForward(response):
    """Detect excessive redirections."""
    try:
        if not response or not hasattr(response, "history"):
            return 0
        return 1 if len(response.history) > 2 else 0
    except:
        return 0


# ===============================
# Main Feature Extraction Function
# ===============================
def featureExtraction(url, label=None):
    """
    Extracts 16 numeric phishing detection features from a given URL.
    
    Args:
        url (str): The URL to analyze
        label (int, optional): Ground truth label (0=legitimate, 1=phishing)
    
    Returns:
        list: Feature values [16 features] or [16 features + label]
    """
    features = []
    
    try:
        # 1-8: Address Bar-based Features
        features.append(havingIP(url))
        features.append(haveAtSign(url))
        features.append(getLength(url))
        features.append(getDepth(url))
        features.append(redirection(url))
        features.append(httpsDomain(url))
        features.append(tinyURL(url))
        features.append(prefixSuffix(url))

        # 9-12: Domain-based Features
        features.append(checkDnsRecord(url))
        features.append(webTraffic(url))
        features.append(domainAge(url))
        features.append(domainEnd(url))

        # 13-16: HTML/JavaScript-based Features
        response = None
        try:
            response = requests.get(url, timeout=5, verify=False, 
                                   headers={'User-Agent': 'Mozilla/5.0'})
        except:
            pass
        
        features.append(iframe(response))
        features.append(mouseOver(response))
        features.append(rightClick(response))
        features.append(webForward(response))

        # Add label if provided (for training datasets)
        if label is not None:
            features.append(label)

        return features

    except Exception as e:
        print(f"Error extracting features from {url}: {e}")
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

