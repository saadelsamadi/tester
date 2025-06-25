from flask import Blueprint, request, jsonify
import os
import re
import requests
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import whois
import tempfile
from flask_cors import CORS

full_bp = Blueprint('full', __name__)
CORS(full_bp)
VIRUSTOTAL_API_KEY = "7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb"

def check_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        else:
            return {"error": f"Failed to retrieve data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_url(url_to_check):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        data = {"url": url_to_check}
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            json_response = response.json()
            url_id = json_response["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                return stats
            else:
                return {"error": f"Failed to retrieve analysis, status code: {analysis_response.status_code}"}
        else:
            return {"error": f"Failed to submit URL, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_file_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            return {"error": "File not found in VirusTotal database."}
        else:
            return {"error": f"Failed to retrieve data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "organization": domain_info.org,
        }
    except Exception as e:
        return {"error": str(e)}

def read_email_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        return None

def extract_basic_email_details(msg):
    sender = msg['From']
    recipient = msg['To']
    reply_to = msg['Reply-To']
    return_path = msg['Return-Path']
    date = msg['Date']
    subject = msg['Subject']
    sender_email, sender_name, sender_domain, sender_ip = None, None, None, "Not found"

    if sender:
        match = re.match(r'(.*)<(.*)>', sender)
        if match:
            sender_name = match.group(1).strip()
            sender_email = match.group(2).strip()
        else:
            sender_email = sender.strip()

    if sender_email:
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)$', sender_email)
        sender_domain = domain_match.group(1) if domain_match else None

    spf, dmarc, dkim = "Not found in headers", "Not found", "Not found"
    for header in msg.keys():
        if header.lower() == "received-spf":
            spf = msg[header]
        elif header.lower().startswith("authentication-results"):
            auth_results = msg[header]
            if "dmarc=" in auth_results:
                dmarc_match = re.search(r"dmarc=(\w+)", auth_results)
                dmarc = dmarc_match.group(1) if dmarc_match else "Not found"
            if "dkim=" in auth_results:
                dkim_match = re.search(r"dkim=(\w+)", auth_results)
                dkim = dkim_match.group(1) if dkim_match else "Not found"

    return {
        "date": date,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "reply_to": reply_to,
        "return_path": return_path,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "recipient": recipient,
        "subject": subject,
    }

def extract_urls_from_email(msg):
    urls = []
    try:
        if msg.is_multipart():
            parts = msg.walk()
            body = ""
            for part in parts:
                if part.get_content_type() == 'text/plain':
                    body += part.get_content()
        else:
            body = msg.get_content()

        url_regex = re.compile(r'((?:http|ftp)s?://[^\s/$.?#].[^\s]*)', re.IGNORECASE)
        urls = url_regex.findall(body)
        return urls
    except Exception as e:
        return []

def extract_attachments_from_email(msg, output_dir=None):
    attachments = []
    try:
        if output_dir is None:
            output_dir = tempfile.mkdtemp()
        os.makedirs(output_dir, exist_ok=True)
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if filename:
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as fp:
                    content = part.get_payload(decode=True)
                    fp.write(content)
                attachments.append({
                    "filename": filename,
                    "filepath": filepath,
                    "sha256": hashlib.sha256(content).hexdigest()
                })
        return attachments
    except Exception as e:
        return []

@full_bp.route('/analyze_email', methods=['POST'])
def analyze_email():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        msg = read_email_file(file_path)
        if not msg:
            return jsonify({"error": "Failed to read the email file"}), 400

        email_details = extract_basic_email_details(msg)

        sender_domain = email_details.get('sender_domain')
        virustotal_domain_results = check_virustotal_domain(sender_domain) if sender_domain else None
        whois_info = get_whois_info(sender_domain) if sender_domain else None

        suspicious_words = ["urgent", "invoice", "payment", "sensitive", "action required"]
        suspicious_subject = any(word in email_details.get('subject', '').lower() for word in suspicious_words)

        urls = extract_urls_from_email(msg)
        url_analyses = [{
            "url": url,
            "virustotal": check_virustotal_url(url)
        } for url in urls]

        attachments = extract_attachments_from_email(msg)
        attachment_analyses = [{
            "filename": att["filename"],
            "sha256": att["sha256"],
            "virustotal": check_virustotal_file_hash(att["sha256"])
        } for att in attachments]

        try:
            for att in attachments:
                if os.path.exists(att["filepath"]):
                    os.remove(att["filepath"])
            if os.path.exists(file_path):
                os.remove(file_path)
            os.rmdir(temp_dir)
        except:
            pass

        return jsonify({
            "email_details": email_details,
            "domain_analysis": {
                "virustotal": virustotal_domain_results,
                "whois": whois_info
            },
            "subject_analysis": {
                "is_suspicious": suspicious_subject,
                "suspicious_words_found": [word for word in suspicious_words if word in email_details.get('subject', '').lower()]
            },
            "url_analysis": url_analyses,
            "attachment_analysis": attachment_analyses
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
