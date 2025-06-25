from flask import Blueprint, request, jsonify
import cv2
import numpy as np
from scipy.stats import chisquare
import scipy.fftpack as fftpack
from skimage.measure import shannon_entropy
import os
import uuid
from flask_cors import CORS
import base64
from werkzeug.utils import secure_filename

sstegno_bp = Blueprint('sstegno', __name__)
CORS(sstegno_bp)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_steganography(video_path):
    cap = cv2.VideoCapture(video_path)
    frame_count = 0
    lsb_distribution = []
    lsb_anomaly_detected = False
    dct_anomaly_detected = False
    entropy_anomaly_detected = False

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        frame_count += 1
        if frame_count % 3 != 0:
            continue

        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        lsb_frame = np.bitwise_and(gray_frame, 1)

        unique, counts = np.unique(lsb_frame, return_counts=True)
        if len(counts) == 2:
            lsb_distribution.append(counts)

        dct_transform = fftpack.dct(fftpack.dct(np.float32(gray_frame), axis=0, norm='ortho'), axis=1, norm='ortho')
        if np.mean(dct_transform) > 50:
            dct_anomaly_detected = True

        if shannon_entropy(gray_frame) > 7.5:
            entropy_anomaly_detected = True

    cap.release()

    if lsb_distribution:
        observed = np.sum(lsb_distribution, axis=0)
        expected = np.full_like(observed, np.mean(observed))
        chi_stat, p_value = chisquare(observed, expected)
        if p_value < 0.05:
            lsb_anomaly_detected = True

    if lsb_anomaly_detected or dct_anomaly_detected or entropy_anomaly_detected:
        return "There is hidden message found in video."
    else:
        return "There is no hidden message found in the video."

@sstegno_bp.route('/sstegno', methods=['POST'])
def sstegno_route():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_extension(file.filename):
        return jsonify({'error': 'Unsupported file type'}), 400

    filename = secure_filename(f"{uuid.uuid4().hex}.mp4")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)
        message = detect_steganography(filepath)
        os.remove(filepath)
        return jsonify({'result': message}), 200

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Processing error: {str(e)}'}), 500
