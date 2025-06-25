from flask import Blueprint, request, jsonify
from joblib import load
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import tldextract
import requests
import base64
import time

urlcheck_bp = Blueprint('urlcheck', __name__)

# تحميل النموذج مرة واحدة
model = load("features/model.joblib")

API_KEY = "80622f5e7e38f3b81381aec0be8aa528bf6186411b8dfa92fe9d8084a89b3ddd"

def contains_sensitive_words(text):
    sensitive_words = ['login', 'password', 'admin', 'secure', 'signin', 'account', 'user']
    return sum(word in text.lower() for word in sensitive_words)

def analyze_url_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    features = [
        url.count('.'),  # عدد النقاط
        len(ext.subdomain.split('.')) if ext.subdomain else 0,  # عدد مستويات الـ subdomain
        len(parsed.path.strip('/').split('/')) if parsed.path else 0,  # عدد مستويات المسار
        len(url),  # طول الرابط
        url.count('-'),  # عدد الـ -
        parsed.hostname.count('-') if parsed.hostname else 0,  # عدد الـ - في hostname
        url.count('_'),  # عدد الـ _
        url.count('%'),  # عدد الـ %
        len(parse_qs(parsed.query)) if parsed.query else 0,  # عدد مكونات الاستعلام
        url.count('&'),  # عدد &
        len(re.findall(r'\d', url)),  # عدد الأرقام
        1 if len(url) > 50 else 0,  # هل الرابط طويل؟
        1 if ext.domain in parsed.path else 0,  # هل اسم الدومين موجود في المسار؟
        len(parsed.hostname) if parsed.hostname else 0,  # طول الـ hostname
        len(parsed.path),  # طول المسار
        len(parsed.query),  # طول الاستعلام
        contains_sensitive_words(url) + contains_sensitive_words(parsed.path),  # كلمات حساسة
    ]

    features += [0] * 19  # خصائص إضافية غير مفعلة

    return features

def extract_url_info(url):
    parsed = urlparse(url)
    return {
        "Domain": parsed.netloc,
        "Path": parsed.path,
        "Query": parsed.query,
        "Scheme": parsed.scheme.upper(),
        "Port": parsed.port if parsed.port else ("80" if parsed.scheme == "http" else "443")
    }

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")

def check_virustotal(api_key, url):
    base_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # إرسال الرابط
    response = requests.post(base_url, headers=headers, data=f"url={url}")
    if response.status_code != 200:
        return {"error": f"VirusTotal submission failed with status {response.status_code}"}

    # انتظار النتيجة
    encoded_url = encode_url(url)
    fetch_url = f"{base_url}/{encoded_url}"
    for _ in range(5):
        result = requests.get(fetch_url, headers=headers)
        if result.status_code == 200:
            stats = result.json().get("data", {}).get("attributes", {}).get("last_analysis_stats")
            if stats:
                return result.json()
        time.sleep(5)

    return {"error": "Timeout waiting for VirusTotal analysis"}

@urlcheck_bp.route('/urlcheck', methods=['POST'])
def urlcheck_route():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']

    try:
        features = analyze_url_features(url)
        prediction = model.predict(np.array(features).reshape(1, -1))[0]
        url_info = extract_url_info(url)
        vt_result = check_virustotal(API_KEY, url)

        if "error" in vt_result:
            return jsonify({"error": vt_result["error"]}), 400

        return jsonify({
            "prediction": int(prediction),
            "url_info": url_info,
            "virustotal_result": vt_result
        })

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
