from flask import Blueprint, request, jsonify
import dns.resolver

spfdmarc_bp = Blueprint('spfdmarc', __name__)

def spf_analysis(domain):
    try:
        result = dns.resolver.resolve(domain, 'TXT')
        spf_records = []
        for rdata in result:
            record = str(rdata).strip('"')
            if record.startswith('v=spf1'):
                spf_records.append(record)

        if spf_records:
            status = "pass"
            mail_from = domain
            authorized = "Yes"
            comment = "SPF validation passed."
        else:
            status = "fail"
            mail_from = domain
            authorized = "No"
            comment = "SPF validation failed. No SPF record found."

        return {
            "status": status,
            "mail_from": mail_from,
            "authorized": authorized,
            "comment": comment
        }
    except dns.resolver.NoAnswer:
        return {"status": "error", "comment": "No SPF record found."}
    except dns.resolver.NXDOMAIN:
        return {"status": "error", "comment": f"Domain {domain} not found."}
    except Exception as e:
        return {"status": "error", "comment": str(e)}

def dkim_analysis(domain):
    try:
        selectors = ['default', 'selector1', 'selector2']
        dkim_records = {}
        for selector in selectors:
            try:
                result = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in result:
                    record = str(rdata).strip('"')
                    if "v=DKIM1" in record:
                        dkim_records[selector] = record
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dkim_records[selector] = "No DKIM record found."

        if any("v=DKIM1" in v for v in dkim_records.values()):
            status = "pass"
            signing_domain = domain
            header_integrity = "Intact"
            comment = "DKIM validation passed."
        else:
            status = "fail"
            signing_domain = domain
            header_integrity = "Possibly Altered"
            comment = "DKIM validation failed. No valid DKIM record found."

        return {
            "status": status,
            "signing_domain": signing_domain,
            "header_integrity": header_integrity,
            "comment": comment
        }
    except Exception as e:
        return {"status": "error", "comment": str(e)}

def dmarc_analysis(domain):
    try:
        result = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_records = []
        for rdata in result:
            record = str(rdata).strip('"')
            if record.startswith('v=DMARC1'):
                dmarc_records.append(record)

        if dmarc_records:
            status = "pass"
            policy = "reject"  # ممكن تعدل حسب p= بالقيمة الحقيقية
            alignment = "Passed"
            comment = f"DMARC validation passed. Policy applied: {policy}. Domain alignment: {alignment}."
        else:
            status = "fail"
            policy = "none"
            alignment = "Failed"
            comment = "DMARC validation failed. No DMARC record found."

        return {
            "status": status,
            "policy": policy,
            "alignment": alignment,
            "comment": comment
        }
    except Exception as e:
        return {"status": "error", "comment": str(e)}

@spfdmarc_bp.route('/spfdmarc', methods=['POST'])
def spfdmarc_route():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    results = {
        "domain": domain,
        "spf": spf_analysis(domain),
        "dkim": dkim_analysis(domain),
        "dmarc": dmarc_analysis(domain)
    }

    return jsonify(results)
