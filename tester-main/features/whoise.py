from flask import Blueprint, request, jsonify
import whois

whoise_bp = Blueprint('whoise', __name__)

def perform_whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)

        return {
            "domain_name": domain_info.domain_name,
            "registrar": domain_info.registrar,
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "updated_date": str(domain_info.updated_date),
            "name_servers": domain_info.name_servers,
            "status": domain_info.status,
            "organization": domain_info.org
        }
    except Exception as e:
        return {"error": str(e)}

@whoise_bp.route('/whoise', methods=['POST'])
def whoise_route():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing "domain" in request'}), 400

    domain = data['domain']
    result = perform_whois_lookup(domain)
    return jsonify(result)
