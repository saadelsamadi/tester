from flask import Blueprint, request, jsonify
import os
import subprocess
import sys
import requests
import time

fullapi_bp = Blueprint('fullapi', __name__)

BASE_PATH = r'C:\Users\bios\PycharmProjects\Features'

API_KEY = '7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb'

def get_script_result(filename):
    file_path = os.path.join(BASE_PATH, filename)
    if not os.path.exists(file_path):
        return None
    try:
        result = subprocess.run(
            [sys.executable, file_path],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout.strip() if result.returncode == 0 else f"Error: {result.stderr.strip()}"
    except Exception as e:
        return f"Execution failed: {str(e)}"

def upload_file(file_obj, filename):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': API_KEY}
    files = {'file': (filename, file_obj)}
    response = requests.post(url, headers=headers, files=files)
    return (response.json()['data']['id'] if response.status_code == 200 else (None, response.json()))

def check_file_status(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json().get('data', {})
        status = data.get('attributes', {}).get('status')
        if status == 'completed':
            stats = data['attributes'].get('stats', {})
            return {'file_id': analysis_id, 'malicious': stats.get('malicious', 0), 'undetected': stats.get('undetected', 0)}
        return {'status': status}
    return None

@fullapi_bp.route('/general_apis/checkspfdmark', methods=['POST'])
def get_spfdmarc():
    result = get_script_result('spfdmarc.py')
    return jsonify_response('spfdmarc.py', result)

@fullapi_bp.route('/general_apis/vid_stegnography', methods=['POST'])
def get_sstegno():
    result = get_script_result('sstegno.py')
    return jsonify_response('sstegno.py', result)

@fullapi_bp.route('/general_apis/stegnography', methods=['POST'])
def get_stegnography():
    result = get_script_result('stegnography.py')
    return jsonify_response('stegnography.py', result)

@fullapi_bp.route('/general_apis/check_attachment', methods=['POST'])
def check_attachment():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    filename = file.filename
    analysis_id_or_error = upload_file(file, filename)
    if isinstance(analysis_id_or_error, tuple):
        _, error = analysis_id_or_error
        return jsonify({'error': 'File upload failed', 'details': error}), 500
    analysis_id = analysis_id_or_error
    for _ in range(12):
        time.sleep(20)
        result = check_file_status(analysis_id)
        if result and result.get('status') != 'queued' and 'malicious' in result:
            return jsonify(result)
    return jsonify({'error': 'File analysis did not complete in time'}), 504

@fullapi_bp.route('/general_apis', methods=['POST'])
def get_all_results():
    files = {
        'checkspfdmark': get_script_result('spfdmarc.py'),
        'vid_stegnography': get_script_result('sstegno.py'),
        'stegnography': get_script_result('stegnography.py'),
        'check_attachment': get_script_result('checkattach.py'),
    }
    return jsonify({'status': 'success', 'data': files})

def jsonify_response(filename, result):
    return jsonify({
        'status': 'success' if result else 'error',
        'filename': filename,
        'result': result if result else f'File {filename} not found'
    }), 200 if result else 404
