from flask import Blueprint, request, jsonify
import numpy as np
from joblib import load
import re
from urllib.parse import urlparse, parse_qs
import tldextract

api_bp = Blueprint('api', __name__)

def contains_sensitive_words(text):
    sensitive_words = ['login', 'password', 'admin', 'secure', 'login', 'signin', 'account', 'user']
    return sum(1 for word in sensitive_words if word in text.lower())

def is_external_url(url, domain):
    return domain not in url

def analyze_url(url):
    features = []

    num_dots = url.count('.')
    features.append(num_dots)

    ext = tldextract.extract(url)
    subdomain_level = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features.append(subdomain_level)

    path_level = len(urlparse(url).path.strip('/').split('/')) if urlparse(url).path else 0
    features.append(path_level)

    url_length = len(url)
    features.append(url_length)

    num_dash = url.count('-')
    features.append(num_dash)

    hostname = urlparse(url).hostname
    num_dash_in_hostname = hostname.count('-') if hostname else 0
    features.append(num_dash_in_hostname)

    num_underscore = url.count('_')
    features.append(num_underscore)

    num_percent = url.count('%')
    features.append(num_percent)

    query = urlparse(url).query
    num_query_components = len(parse_qs(query)) if query else 0
    features.append(num_query_components)

    num_ampersand = url.count('&')
    features.append(num_ampersand)

    num_numeric_chars = len(re.findall(r'\d', url))
    features.append(num_numeric_chars)

    random_string = 1 if len(url) > 50 else 0
    features.append(random_string)

    path = urlparse(url).path
    domain_in_paths = 1 if ext.domain in path else 0
    features.append(domain_in_paths)

    hostname_length = len(hostname) if hostname else 0
    features.append(hostname_length)

    path_length = len(urlparse(url).path)
    features.append(path_length)

    query_length = len(urlparse(url).query)
    features.append(query_length)

    sensitive_words_count = contains_sensitive_words(url) + contains_sensitive_words(urlparse(url).path)
    features.append(sensitive_words_count)

    pct_ext_hyperlinks = 0  
    features.append(pct_ext_hyperlinks)

    pct_ext_resource_urls = 0  
    features.append(pct_ext_resource_urls)

    ext_favicon = 1 if "favicon" in url else 0  
    features.append(ext_favicon)

    insecure_forms = 0  
    features.append(insecure_forms)

    relative_form_action = 1 if 'action' in url else 0  
    features.append(relative_form_action)

    ext_form_action = 1 if is_external_url(urlparse(url).geturl(), ext.domain) else 0
    features.append(ext_form_action)

    abnormal_form_action = 0  
    features.append(abnormal_form_action)

    pct_null_self_redirect_hyperlinks = 0  
    features.append(pct_null_self_redirect_hyperlinks)

    frequent_domain_name_mismatch = 0  
    features.append(frequent_domain_name_mismatch)

    submit_info_to_email = 0  
    features.append(submit_info_to_email)

    iframe_or_frame = 0  
    features.append(iframe_or_frame)

    missing_title = 0  
    features.append(missing_title)

    images_only_in_form = 0  
    features.append(images_only_in_form)

    subdomain_level_rt = 0  
    features.append(subdomain_level_rt)

    url_length_rt = 0  
    features.append(url_length_rt)

    pct_ext_resource_urls_rt = 0  
    features.append(pct_ext_resource_urls_rt)

    abnormal_ext_form_action_r = 0  
    features.append(abnormal_ext_form_action_r)

    ext_meta_script_link_rt = 0  
    features.append(ext_meta_script_link_rt)

    pct_ext_null_self_redirect_hyperlinks_rt = 0  
    features.append(pct_ext_null_self_redirect_hyperlinks_rt)

    return features

# تأكد إن ملف الموديل موجود في نفس المسار أو عدل المسار هنا
model = load("model.joblib")

@api_bp.route('/api', methods=['POST'])
def api_route():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = analyze_url(url)
    input_array = np.array(features).reshape(1, -1)
    prediction = model.predict(input_array)
    return jsonify({'prediction': prediction.tolist()})
