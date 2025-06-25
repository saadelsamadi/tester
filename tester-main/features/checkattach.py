from flask import Blueprint, request, jsonify
import requests
import time

checkattach_bp = Blueprint('checkattach', __name__)

API_KEY = '7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb'

def upload_file(file_obj, filename):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY
    }
    files = {
        'file': (filename, file_obj)
    }

    response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        return None, response.json()

def check_file_status(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {
        'x-apikey': API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        data = json_response.get('data', {})
        attributes = data.get('attributes', {})
        status = attributes.get('status')

        if status == 'completed':
            stats = attributes.get('stats', {})
            return {
                'file_id': analysis_id,
                'malicious': stats.get('malicious', 0),
                'undetected': stats.get('undetected', 0)
            }

        return {'status': status}
    else:
        return None

@checkattach_bp.route('/checkattach', methods=['POST'])
def check_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    filename = file.filename

    analysis_id_or_error = upload_file(file, filename)
    if isinstance(analysis_id_or_error, tuple):
        _, error = analysis_id_or_error
        return jsonify({'error': 'File upload failed', 'details': error}), 500
    else:
        analysis_id = analysis_id_or_error

    attempts = 0
    result = None
    while attempts < 12:
        time.sleep(20)
        status_result = check_file_status(analysis_id)

        if isinstance(status_result, dict):
            if status_result.get('status') != 'queued' and 'malicious' in status_result:
                result = status_result
                break
        attempts += 1

    if result:
        return jsonify(result)
    else:
        return jsonify({'error': 'File analysis did not complete in time'}), 504
