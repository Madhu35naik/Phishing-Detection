"""
Enhanced Attack Classification & Prevention System
Educational Version with Advanced Features
"""

from FeatureExtraction import feature_names
from datetime import datetime

# ===============================
# ATTACK TYPE CLASSIFICATION
# ===============================

def classify_attack_type(features):
    """
    Classify PRIMARY attack type with detailed technical explanation.
    """
    if not isinstance(features, (list, tuple)) or len(features) < len(feature_names):
        return ["INVALID_FEATURES"]

    feature_dict = dict(zip(feature_names, features))
    
    # Priority-based detection
    suspicious_count = sum([
        feature_dict['Have_IP'],
        feature_dict['TinyURL'],
        feature_dict['Prefix/Suffix'],
        feature_dict['https_Domain'],
        feature_dict['Redirection'],
        feature_dict['Domain_Age'],
        feature_dict['DNS_Record'],
        feature_dict['iFrame']
    ])
    
    if suspicious_count >= 5:
        return ['SOPHISTICATED_MULTI_VECTOR_ATTACK']
    if feature_dict['Have_IP']:
        return ['IP_BASED_PHISHING']
    if feature_dict['Prefix/Suffix']:
        return ['TYPOSQUATTING_HOMOGRAPH']
    if feature_dict['https_Domain']:
        return ['DOMAIN_SPOOFING']
    if feature_dict['iFrame']:
        return ['IFRAME_OVERLAY_PHISHING']
    if feature_dict['DNS_Record']:
        return ['DNS_ANOMALY_PHISHING']
    if feature_dict['Redirection']:
        return ['OPEN_REDIRECT_PHISHING']
    if feature_dict['TinyURL']:
        return ['URL_SHORTENER_PHISHING']
    if feature_dict['Domain_Age']:
        return ['NEW_DOMAIN_PHISHING']
    if feature_dict['Mouse_Over'] or feature_dict['Right_Click']:
        return ['SOCIAL_ENGINEERING_PHISHING']
    
    return ['GENERAL_PHISHING']


# ===============================
# ENHANCED PREVENTION DATABASE
# ===============================

ENHANCED_PREVENTION = {
    'IP_BASED_PHISHING': {
        'severity': 'HIGH',
        'risk_score': 85,
        'warning': '🛑 IP-Based URL Detected!',
        
        # Technical Explanation (Educational)
        'technical_details': {
            'description': 'The URL uses a raw IP address instead of a domain name. Legitimate websites always use proper domain names (e.g., amazon.com) rather than IP addresses.',
            'why_dangerous': 'Attackers use IP addresses to avoid domain registration tracking and to quickly set up phishing sites that bypass domain-based security filters.',
            'common_targets': ['Banking sites', 'E-commerce platforms', 'Corporate login portals'],
            'attack_vector': 'Direct IP access bypasses DNS-based security measures and domain reputation systems.'
        },
        
        # User-Friendly Advice
        'advice': [
            'Never enter login credentials on IP-based URLs',
            'Legitimate websites use proper domain names, not raw IP addresses',
            'Close this page immediately and verify the correct website URL',
            'Report this URL to your IT security team'
        ],
        
        # Educational Content
        'how_to_identify': [
            'Look for numbers separated by dots in the URL (e.g., 192.168.1.1)',
            'Check if the address bar shows an IP instead of a domain name',
            'Legitimate sites will always have a readable domain (e.g., google.com)'
        ],
        
        # Real-World Examples
        'real_examples': [
            'http://203.0.113.45/paypal-login',
            'https://198.51.100.10/secure-banking',
            'http://192.168.1.1/verify-account'
        ],
        
        # Prevention Techniques
        'prevention_techniques': [
            'Use browser extensions that flag IP-based URLs',
            'Enable DNS filtering on your network',
            'Always access websites through bookmarks or search engines',
            'Train employees to recognize IP addresses in URLs'
        ],
        
        # Incident Response
        'if_clicked': [
            'Immediately close the browser tab/window',
            'Do not enter any information',
            'Clear browser cache and cookies',
            'Run a security scan on your device',
            'Report to IT security if received via corporate email',
            'Change passwords if you entered any credentials'
        ]
    },
    
    'URL_SHORTENER_PHISHING': {
        'severity': 'MEDIUM',
        'risk_score': 60,
        'warning': '⚠️ URL Shortener Detected',
        
        'technical_details': {
            'description': 'The URL uses a link shortening service (like bit.ly, tinyurl.com) that hides the true destination.',
            'why_dangerous': 'Shortened URLs obscure the real destination, making it impossible to verify legitimacy before clicking. Attackers exploit this to hide malicious links.',
            'common_targets': ['Social media users', 'Email recipients', 'SMS/messaging platforms'],
            'attack_vector': 'Social engineering through trusted-looking short links that redirect to phishing pages.'
        },
        
        'advice': [
            'Use URL expander tools (like unshorten.it) to see the real destination',
            'Never click shortened links from unknown sources or suspicious emails',
            'Verify the sender before clicking any shortened URL',
            'Be extra cautious with shortened links asking for login or payment info'
        ],
        
        'how_to_identify': [
            'Look for domains like bit.ly, tinyurl.com, goo.gl, t.co',
            'URLs are typically very short (fewer than 20 characters)',
            'Contains random characters after the domain (e.g., bit.ly/xK9m2q)'
        ],
        
        'real_examples': [
            'http://bit.ly/3xK9mPq',
            'http://tinyurl.com/malicious123',
            'https://t.co/suspicious'
        ],
        
        'prevention_techniques': [
            'Install browser extensions that preview shortened URLs',
            'Use URL expander websites before clicking',
            'Check sender reputation before clicking',
            'Educate users about shortened URL risks'
        ],
        
        'if_clicked': [
            'Check where you landed - verify the domain',
            'Do not proceed if the destination looks suspicious',
            'Close the page if it asks for personal information',
            'Report the shortened URL to the service provider'
        ]
    },
    
    'TYPOSQUATTING_HOMOGRAPH': {
        'severity': 'CRITICAL',
        'risk_score': 95,
        'warning': '🚨 Brand Impersonation Detected',
        
        'technical_details': {
            'description': 'The domain name closely resembles a legitimate brand by using typos, extra characters, or similar-looking characters (homograph attack).',
            'why_dangerous': 'Users may not notice subtle differences and believe they\'re on the legitimate website, leading to credential theft or malware installation.',
            'common_targets': ['Banking sites', 'Payment processors', 'Popular brands', 'Government websites'],
            'attack_vector': 'Visual deception through domain names that look nearly identical to legitimate brands.'
        },
        
        'advice': [
            'Carefully check the domain spelling - it may look similar to a legitimate brand',
            'Look for unusual characters, extra dashes, or misspellings',
            'Compare with the official website URL from search engine or bookmarks',
            'Do NOT enter any personal information, passwords, or payment details',
            'Report this to the brand being impersonated'
        ],
        
        'how_to_identify': [
            'Extra dashes or hyphens (paypal-secure.com instead of paypal.com)',
            'Additional words (amazon-login.com instead of amazon.com)',
            'Misspellings (microsft.com instead of microsoft.com)',
            'Similar-looking characters (goog1e.com using "1" instead of "l")',
            'Different top-level domain (paypal.net instead of paypal.com)'
        ],
        
        'real_examples': [
            'paypal-secure-login.com (real: paypal.com)',
            'amazon-verify-account.com (real: amazon.com)',
            'microsoft-support.net (real: microsoft.com)',
            'app1e.com (real: apple.com - note the "1" instead of "l")'
        ],
        
        'prevention_techniques': [
            'Always use bookmarks for important websites',
            'Type URLs directly instead of clicking links',
            'Use password managers that auto-fill only on correct domains',
            'Enable browser warnings for suspicious domains',
            'Check SSL certificates for domain validation'
        ],
        
        'if_clicked': [
            '🚨 CRITICAL: Do not enter any information',
            'Close the page immediately',
            'Clear browser cache',
            'Report to the legitimate brand\'s security team',
            'If credentials entered: IMMEDIATELY change passwords',
            'Monitor accounts for unauthorized activity',
            'Consider credit monitoring if financial info was entered'
        ]
    },
    
    'SOPHISTICATED_MULTI_VECTOR_ATTACK': {
        'severity': 'CRITICAL',
        'risk_score': 100,
        'warning': '☢️ ADVANCED ATTACK DETECTED',
        
        'technical_details': {
            'description': 'This URL exhibits 5 or more suspicious indicators simultaneously, suggesting a sophisticated, well-crafted phishing campaign.',
            'why_dangerous': 'Multi-vector attacks combine multiple techniques to bypass security measures and increase success rate. Often part of advanced persistent threats (APT).',
            'common_targets': ['High-value targets', 'Corporate executives', 'Financial institutions', 'Government agencies'],
            'attack_vector': 'Layered approach using multiple evasion and deception techniques simultaneously.'
        },
        
        'advice': [
            '🚨 CRITICAL: This URL shows 5+ phishing indicators simultaneously',
            'This is a sophisticated, well-crafted phishing attack',
            'IMMEDIATELY close this page - do not interact with it',
            'Clear your browser cache and run an antivirus scan',
            'Report this to your IT security/incident response team urgently',
            'Do NOT enter any information under any circumstances'
        ],
        
        'how_to_identify': [
            'Multiple red flags present (IP address + shortener + fake SSL, etc.)',
            'Combines techniques from different attack categories',
            'Often uses social engineering alongside technical exploits',
            'May appear more legitimate due to effort invested'
        ],
        
        'real_examples': [
            'http://192.168.1.1/paypal-secure/bit.ly/verify (IP + typosquatting + shortener)',
            'http://https-bank-login.com//redirect (domain spoofing + redirection)',
        ],
        
        'prevention_techniques': [
            'Deploy multi-layered security (email filters + web filters + endpoint protection)',
            'Implement security awareness training',
            'Use threat intelligence feeds',
            'Enable advanced email authentication (DMARC, SPF, DKIM)',
            'Conduct regular phishing simulation exercises'
        ],
        
        'if_clicked': [
            '⚠️ IMMEDIATE ACTIONS REQUIRED:',
            '1. Disconnect from network immediately',
            '2. Do not enter any information',
            '3. Run full system antivirus/malware scan',
            '4. Contact IT security team immediately',
            '5. Document the incident (take screenshots)',
            '6. If credentials entered: Force password reset on all accounts',
            '7. Monitor for unauthorized access attempts',
            '8. Consider engaging incident response team',
            '9. File incident report with relevant authorities'
        ]
    },
    
    'LEGITIMATE': {
        'severity': 'LOW',
        'risk_score': 0,
        'warning': '✅ Site Appears Safe',
        
        'technical_details': {
            'description': 'This URL passed security checks and exhibits characteristics of a legitimate website.',
            'why_safe': 'URL structure follows best practices, domain has proper registration, and no suspicious patterns detected.',
            'confidence_note': 'While this URL appears safe, always verify you\'re on the correct domain.'
        },
        
        'advice': [
            'This URL passed security checks and appears legitimate',
            'Always verify you\'re on the correct domain before entering sensitive info',
            'Look for HTTPS and a valid SSL certificate (padlock icon)',
            'Stay vigilant - even legitimate sites can be compromised',
            'Never share passwords or financial information unless absolutely certain'
        ],
        
        'how_to_identify': [
            'Well-known, established domain name',
            'Proper HTTPS with valid SSL certificate',
            'No suspicious characters or patterns in URL',
            'Matches official domain from search engines'
        ],
        
        'best_practices': [
            'Always use two-factor authentication (2FA) when available',
            'Use unique, strong passwords for each site',
            'Keep browser and security software updated',
            'Verify SSL certificate details before entering sensitive data',
            'Use official mobile apps when possible',
            'Enable account activity notifications'
        ]
    }
}


# ===============================
# RISK SCORING SYSTEM
# ===============================

def calculate_risk_score(features, attack_types):
    """
    Calculate numerical risk score (0-100) based on features and attack types.
    """
    base_score = 0
    
    # Get base score from attack type
    for attack in attack_types:
        info = ENHANCED_PREVENTION.get(attack, {})
        attack_score = info.get('risk_score', 50)
        base_score = max(base_score, attack_score)
    
    # Adjust based on feature count
    feature_dict = dict(zip(feature_names, features))
    suspicious_features = sum([
        feature_dict.get('Have_IP', 0),
        feature_dict.get('TinyURL', 0),
        feature_dict.get('Prefix/Suffix', 0),
        feature_dict.get('https_Domain', 0),
        feature_dict.get('Redirection', 0),
        feature_dict.get('Domain_Age', 0),
        feature_dict.get('DNS_Record', 0),
        feature_dict.get('iFrame', 0)
    ])
    
    # Add bonus risk for multiple suspicious features
    if suspicious_features >= 3:
        base_score = min(100, base_score + (suspicious_features - 2) * 5)
    
    return base_score


# ===============================
# EDUCATIONAL CONTENT GENERATOR
# ===============================

def generate_educational_content(attack_types, features):
    """
    Generate comprehensive educational content about the detected threat.
    """
    educational_content = {
        'threat_overview': {},
        'how_it_works': [],
        'why_dangerous': [],
        'identification_tips': [],
        'real_world_examples': [],
        'prevention_steps': [],
        'incident_response': [],
        'further_reading': []
    }
    
    for attack in attack_types:
        info = ENHANCED_PREVENTION.get(attack, {})
        tech_details = info.get('technical_details', {})
        
        if tech_details:
            educational_content['threat_overview'] = {
                'attack_type': attack.replace('_', ' ').title(),
                'description': tech_details.get('description', ''),
                'severity': info.get('severity', 'MEDIUM'),
                'risk_score': info.get('risk_score', 50)
            }
            
            educational_content['how_it_works'].append({
                'attack_vector': tech_details.get('attack_vector', ''),
                'common_targets': tech_details.get('common_targets', [])
            })
            
            educational_content['why_dangerous'].append(
                tech_details.get('why_dangerous', '')
            )
        
        educational_content['identification_tips'].extend(
            info.get('how_to_identify', [])
        )
        
        educational_content['real_world_examples'].extend(
            info.get('real_examples', [])
        )
        
        educational_content['prevention_steps'].extend(
            info.get('prevention_techniques', [])
        )
        
        educational_content['incident_response'].extend(
            info.get('if_clicked', [])
        )
    
    # Add general resources
    educational_content['further_reading'] = [
        'NIST Phishing Prevention Guidelines',
        'CISA Cybersecurity Awareness',
        'Anti-Phishing Working Group (APWG)',
        'Google Safe Browsing Transparency Report',
        'Microsoft Security Intelligence'
    ]
    
    return educational_content


# ===============================
# ENHANCED ANALYSIS FUNCTION
# ===============================

def analyze_phishing_attack(features, prediction, confidence):
    """
    Complete enhanced analysis with educational content.
    """
    attack_types = classify_attack_type(features) if prediction == 1 else ["LEGITIMATE"]
    
    # Get basic prevention info
    prevention_info = {}
    for attack in attack_types:
        info = ENHANCED_PREVENTION.get(attack, {})
        prevention_info = {
            "severity": info.get('severity', 'MEDIUM'),
            "risk_score": info.get('risk_score', 50),
            "warnings": [info.get('warning', '')],
            "advice": info.get('advice', []),
            "technical_details": info.get('technical_details', {}),
            "how_to_identify": info.get('how_to_identify', []),
            "real_examples": info.get('real_examples', []),
            "prevention_techniques": info.get('prevention_techniques', []),
            "if_clicked": info.get('if_clicked', [])
        }
    
    # Calculate risk score
    risk_score = calculate_risk_score(features, attack_types)
    
    # Generate educational content
    educational_content = generate_educational_content(attack_types, features)
    
    return {
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "confidence": confidence,
        "attack_types": attack_types,
        "risk_score": risk_score,
        "prevention": prevention_info,
        "educational_content": educational_content,
        "timestamp": datetime.utcnow().isoformat(),
        "features_detected": dict(zip(feature_names, features))
    }