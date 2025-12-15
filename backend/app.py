# app.py (ENHANCED VERSION - WITH URL VALIDATION, FEEDBACK REMOVED)

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
from datetime import datetime
import traceback
import re
from urllib.parse import urlparse

# Removed: log_user_feedback import
from utils.Logger import log_scan_result, get_scan_reports

# Import your feature extraction & attack classification
from FeatureExtraction import featureExtraction, feature_names
from AttackClassification import analyze_phishing_attack, calculate_risk_score, generate_educational_content

# ============================================================
# URL VALIDATION UTILITY
# ============================================================
def validate_url(url):
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"
    
    url = url.strip()
    
    if len(url) < 4:
        return False, "URL is too short"
    
    if ' ' in url:
        return False, "URL contains spaces"
    
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url_with_scheme = 'http://' + url
    else:
        url_with_scheme = url

    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    try:
        parsed = urlparse(url_with_scheme)
        
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format"
        
        if '.' not in parsed.netloc and parsed.netloc != 'localhost' and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc):
            return False, "Invalid domain name"
        
        if not url_pattern.match(url_with_scheme):
            return False, "Invalid URL structure"
        
        return True, url_with_scheme
        
    except Exception:
        return False, "URL parsing error"


def get_url_validation_guidance():
    return {
        "valid_examples": [
            "https://www.example.com",
            "http://example.com/path",
            "https://subdomain.example.co.uk",
            "http://192.168.1.1",
            "https://example.com:8080/path"
        ],
        "invalid_examples": [
            "just text",
            "example",
            "www.example",
            "htp://example.com",
            "example .com"
        ],
        "tips": [
            "URL must start with http:// or https://",
            "URL should not contain spaces",
            "Domain name must be valid",
            "Correct URL structure is required"
        ]
    }


# ============================================================
# SETUP
# ============================================================
app = Flask(__name__)
CORS(app)
MAX_BATCH_SIZE = 50 

MODEL_PATH = "phishing_Model.pkl"
try:
    model_data = joblib.load(MODEL_PATH)
    if isinstance(model_data, dict):
        model = model_data["model"]
        model_name = model_data.get("model_name", "Unknown Model")
    else:
        model = model_data
        model_name = type(model).__name__
except Exception:
    model = None
    model_name = "Rule-Based Fallback"


# ============================================================
# ROOT, HEALTH CHECK
# ============================================================
@app.route("/")
def home():
    return jsonify({"service": "Phishing Detection API", "version": "2.3 (URL Validation)"})

@app.route("/api/health")
def health():
    return jsonify({
        "status": "OK",
        "model_loaded": model is not None,
        "logging_status": "Enabled",
        "validation": "Active"
    })


# ============================================================
# URL VALIDATION ENDPOINT
# ============================================================
@app.route("/api/validate-url", methods=["POST"])
def validate_url_endpoint():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "")
        
        is_valid, result = validate_url(url)
        
        if is_valid:
            return jsonify({
                "valid": True,
                "formatted_url": result,
                "message": "URL ready for scanning"
            })
        else:
            return jsonify({
                "valid": False,
                "error": result,
                "guidance": get_url_validation_guidance()
            }), 400
            
    except Exception:
        return jsonify({
            "valid": False,
            "error": "Validation error",
            "guidance": get_url_validation_guidance()
        }), 500


# ============================================================
# MAIN SCAN API
# ============================================================
@app.route("/api/scan", methods=["POST"])
def scan_url():
    try:
        data = request.get_json(force=True)
        url = data.get("url")
        
        is_valid, validation_result = validate_url(url)
        if not is_valid:
            return jsonify({
                "error": "Invalid URL",
                "message": validation_result,
                "guidance": get_url_validation_guidance()
            }), 400
        
        url = validation_result

        features = featureExtraction(url, None)
        features_np = np.array(features).reshape(1, -1)

        if model:
            pred = int(model.predict(features_np)[0])
            confidence = float(model.predict_proba(features_np)[0][pred] * 100) if hasattr(model, "predict_proba") else 90.0
        else:
            pred = 1
            confidence = 50.0

        result = analyze_phishing_attack(features, pred, confidence)
        risk_score = calculate_risk_score(features, result["attack_types"])
        educational_content = generate_educational_content(result["attack_types"], features)

        final_response_data = {
            "url": url,
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "risk_score": risk_score,
            "attack_types": result["attack_types"],
            "prevention": result["prevention"],
            "educational_content": educational_content,
            "features": dict(zip(feature_names, features)),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        log_response = log_scan_result(final_response_data, is_batch=False)
        final_response_data["log_id"] = log_response.get("log_id")

        return jsonify(final_response_data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ============================================================
# BATCH API
# ============================================================
@app.route("/api/batch", methods=["POST"])
def batch_scan():
    try:
        data = request.get_json(force=True)
        urls = data.get("urls", [])

        if not isinstance(urls, list) or not urls:
            return jsonify({"error": "Provide a list of URLs"}), 400
        
        urls_to_scan = urls[:MAX_BATCH_SIZE]
        results = []
        validation_errors = []

        for idx, url in enumerate(urls_to_scan):
            is_valid, validation_result = validate_url(url)
            
            if not is_valid:
                validation_errors.append({"index": idx, "url": url, "error": validation_result})
                results.append({
                    "url": url,
                    "prediction": "error",
                    "confidence": 0,
                    "risk_score": 0,
                    "attack_types": ["INVALID_URL"],
                    "error_message": validation_result
                })
                continue
            
            url = validation_result
            scan_result = {"url": url}

            try:
                features = featureExtraction(url, None)
                features_np = np.array(features).reshape(1, -1)
                
                if model:
                    pred = int(model.predict(features_np)[0])
                    confidence = float(model.predict_proba(features_np)[0][pred] * 100) if hasattr(model, "predict_proba") else 90.0
                else:
                    pred = 1
                    confidence = 50.0

                result = analyze_phishing_attack(features, pred, confidence)
                risk_score = calculate_risk_score(features, result["attack_types"])
                
                scan_result.update({
                    "prediction": result["prediction"],
                    "confidence": result["confidence"],
                    "risk_score": risk_score,
                    "attack_types": result["attack_types"]
                })
                
            except Exception as e:
                scan_result.update({
                    "prediction": "error",
                    "confidence": 0,
                    "risk_score": 0,
                    "attack_types": ["PROCESSING_ERROR"],
                    "error_message": str(e)
                })

            results.append(scan_result)

        summary = {
            "phishing_count": sum(1 for r in results if r["prediction"] == "phishing"),
            "legitimate_count": sum(1 for r in results if r["prediction"] == "legitimate"),
            "error_count": sum(1 for r in results if r["prediction"] == "error"),
            "invalid_url_count": len(validation_errors),
            "high_risk_count": sum(1 for r in results if r.get("risk_score", 0) >= 51),
            "critical_risk_count": sum(1 for r in results if r.get("risk_score", 0) >= 76)
        }
        
        batch_response = {
            "total": len(results),
            "summary": summary,
            "results": results,
            "validation_errors": validation_errors or None,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        log_scan_result(batch_response, is_batch=True)
        
        return jsonify(batch_response)
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Batch processing failed: {e}"}), 500


# ============================================================
# LOGS API
# ============================================================
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        limit = int(request.args.get("limit", 50))
        start_date = request.args.get("start_date")
        report_data = get_scan_reports(limit=limit, start_date=start_date)
        if "error" in report_data:
            return jsonify(report_data), 500
        return jsonify(report_data)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to retrieve logs: {e}"}), 500


# ============================================================
# NO FEEDBACK API ANYMORE
# ============================================================


# ============================================================
# STATS API
# ============================================================
@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "model_info": {
            "name": model_name,
            "loaded": model is not None,
            "features_count": len(feature_names)
        },
        "feature_categories": {
            "address_bar": feature_names[0:8],
            "domain_based": feature_names[8:12],
            "html_based": feature_names[12:16]
        },
        "supported_attacks": [
            "IP_BASED_PHISHING",
            "URL_SHORTENER_PHISHING",
            "TYPOSQUATTING_HOMOGRAPH",
            "DOMAIN_SPOOFING",
            "OPEN_REDIRECT_PHISHING",
            "NEW_DOMAIN_PHISHING",
            "DNS_ANOMALY_PHISHING",
            "IFRAME_OVERLAY_PHISHING",
            "SOCIAL_ENGINEERING_PHISHING",
            "SOPHISTICATED_MULTI_VECTOR_ATTACK"
        ],
        "risk_levels": {
            "low": "0-25",
            "medium": "26-50",
            "high": "51-75",
            "critical": "76-100"
        }
    })


# ============================================================
# RUN SERVER
# ============================================================
if __name__ == "__main__":
    print("\n" + "="*50)
    print(" 🚀 ENHANCED PHISHING DETECTION API (V2.4 - FEEDBACK REMOVED)")
    print("="*50)
    print(" URL: http://localhost:5000")
    print(" Features: URL Validation, Logging")
    print(" Status: Ready")
    print("="*50 + "\n")
    app.run(host="0.0.0.0", port=5000, use_reloader=False)
