from flask import Blueprint, request, jsonify
import socket
import ssl
from urllib.parse import urlparse

ssltls_bp = Blueprint('ssltls', __name__)

def get_ssl_certificate_details(url):
    try:
        # Parse the URL to extract hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        # Connect to the server and retrieve the certificate
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract relevant details
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'Unknown')
        issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
        valid_from = cert.get('notBefore', 'Unknown')
        valid_to = cert.get('notAfter', 'Unknown')

        return {
            'IssuedTo': issued_to,
            'Issuer': issuer,
            'ValidFrom': valid_from,
            'ValidTo': valid_to,
        }
    except Exception as e:
        return {"error": f"Unable to retrieve SSL/TLS certificate details - {str(e)}"}

@ssltls_bp.route('/ssltls', methods=['POST'])
def ssltls_route():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request. 'url' is required."}), 400

        url = data['url'].strip()
        if not url.startswith("https://"):
            url = "https://" + url  # Ensure HTTPS for SSL

        cert_details = get_ssl_certificate_details(url)
        return jsonify(cert_details), 200

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
