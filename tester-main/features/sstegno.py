from flask import Blueprint, request, jsonify
import cv2
import numpy as np
from scipy.stats import chisquare
import scipy.fftpack as fftpack
from skimage.measure import shannon_entropy
import os
import uuid
from flask_cors import CORS
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
    dct_scores = []
    entropy_scores = []

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        frame_count += 1
        if frame_count % 3 != 0:
            continue

        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # LSB distribution
        lsb_frame = np.bitwise_and(gray_frame, 1)
        unique, counts = np.unique(lsb_frame, return_counts=True)
        if len(counts) == 2:
            lsb_distribution.append(counts)

        # DCT mean
        dct_transform = fftpack.dct(fftpack.dct(np.float32(gray_frame), axis=0, norm='ortho'), axis=1, norm='ortho')
        dct_scores.append(np.mean(dct_transform))

        # Entropy
        entropy_scores.append(shannon_entropy(gray_frame))

    cap.release()

    # Aggregate metrics
    lsb_anomaly_detected = False
    dct_anomaly_detected = False
    entropy_anomaly_detected = False

    lsb_p_value = 1.0
    if lsb_distribution:
        observed = np.sum(lsb_distribution, axis=0)
        expected = np.full_like(observed, np.mean(observed))
        chi_stat, lsb_p_value = chisquare(observed, expected)
        if lsb_p_value < 0.05:
            lsb_anomaly_detected = True

    avg_dct = np.mean(dct_scores) if dct_scores else 0
    if avg_dct > 50:
        dct_anomaly_detected = True

    avg_entropy = np.mean(entropy_scores) if entropy_scores else 0
    if avg_entropy > 7.5:
        entropy_anomaly_detected = True

    # Confidence calculation (0-1)
    confidence = 0.0
    if lsb_anomaly_detected:
        confidence += 0.4
    if dct_anomaly_detected:
        confidence += 0.3
    if entropy_anomaly_detected:
        confidence += 0.3

    # Build result string
    if confidence > 0.5:
        result = f"There is hidden message found in video (confidence: {confidence:.2f})"
    else:
        result = f"There is no hidden message found in the video (confidence: {confidence:.2f})"

    # Extra details for debugging (optional, comment out if not needed)
    result_details = {
        "lsb_p_value": lsb_p_value,
        "avg_dct": avg_dct,
        "avg_entropy": avg_entropy,
        "confidence": round(confidence, 2)
    }

    return {
        "summary": result,
        "details": result_details
    }

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
        analysis = detect_steganography(filepath)
        os.remove(filepath)
        return jsonify({
            'result': analysis["summary"],
            'metrics': analysis["details"]
        }), 200

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Processing error: {str(e)}'}), 500
