from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os
import string
import math

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)

def chi_square_lsb_test(image):
    pixels = list(image.getdata())
    freq_lsb_0 = 0
    freq_lsb_1 = 0

    for pixel in pixels:
        for val in pixel[:3]:
            lsb = val & 1
            if lsb == 0:
                freq_lsb_0 += 1
            else:
                freq_lsb_1 += 1

    total = freq_lsb_0 + freq_lsb_1
    expected = total / 2

    if expected == 0:
        return 0

    chi_square = ((freq_lsb_0 - expected) ** 2) / expected + ((freq_lsb_1 - expected) ** 2) / expected
    return chi_square

def lsb_entropy(image):
    bits = []
    for pixel in image.getdata():
        for val in pixel[:3]:
            bits.append(val & 1)
    total = len(bits)
    if total == 0:
        return 0
    p1 = sum(bits) / total
    p0 = 1 - p1
    if p0 in [0,1]:
        return 0
    entropy = -(p1 * math.log2(p1) + p0 * math.log2(p0))
    return entropy

def extract_message(image):
    bits = ""
    for pixel in image.getdata():
        for val in pixel[:3]:
            bits += str(val & 1)
    end_signal = '11111110'
    if end_signal not in bits:
        return None
    message = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if byte == end_signal:
            break
        try:
            message += chr(int(byte,2))
        except:
            return None
    printable_chars = set(string.printable)
    if all(c in printable_chars for c in message):
        return message
    return None

def is_stego_present(image, chi_threshold=10, entropy_threshold=0.95):
    chi_val = chi_square_lsb_test(image)
    entropy = lsb_entropy(image)
    if chi_val < chi_threshold:
        return True
    if entropy > entropy_threshold:
        return True
    return False

@stegnography_bp.route('/stegnography', methods=['POST'])
def detect_stego():
    image = None

    if 'image' in request.files:
        file = request.files['image']
        if file.filename == '':
            return jsonify({"hidden": False, "message": None}), 400

        filename = file.filename
        save_path = os.path.join(os.getcwd(), filename)
        try:
            file.save(save_path)
            image = Image.open(save_path).convert("RGB")
            os.remove(save_path)
        except Exception:
            return jsonify({"hidden": False, "message": None}), 400

    elif request.is_json and 'image_base64' in request.json:
        try:
            base64_str = request.json['image_base64']
            if 'base64,' in base64_str:
                base64_str = base64_str.split('base64,')[1]
            image_data = base64.b64decode(base64_str)
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
        except Exception:
            return jsonify({"hidden": False, "message": None}), 400
    else:
        return jsonify({"hidden": False, "message": None}), 400

    hidden = False
    message = None

    if is_stego_present(image):
        message = extract_message(image)
        if message:
            hidden = True
        else:
            hidden = True  # Even if message not extracted, indicators suggest hidden content

    return jsonify({
        "hidden": hidden,
        "message": message
    })
