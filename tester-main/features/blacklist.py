from flask import Blueprint, request, jsonify
import requests

blacklist_bp = Blueprint('blacklist', __name__)

API_KEY = "7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb"

def check_domain_virustotal(api_key, domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_votes = stats.get("malicious", 0)
            suspicious_votes = stats.get("suspicious", 0)

            return {
                "domain": domain,
                "malicious_votes": malicious_votes,
                "suspicious_votes": suspicious_votes,
                "status": "alert" if malicious_votes > 0 or suspicious_votes > 0 else "safe"
            }
        else:
            return {"error": f"Unable to query VirusTotal (Status Code: {response.status_code})"}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

@blacklist_bp.route('/blacklist', methods=['POST'])
def blacklist_route():
    try:
        data = request.json
        domain = data.get("domain")
        if not domain:
            return jsonify({"error": "Missing 'domain' field in request"}), 400

        result = check_domain_virustotal(API_KEY, domain)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
