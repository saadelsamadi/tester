from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os
import string
import numpy as np

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)

def chi_square_lsb_test(image):
    """
    Chi-Square test focused on LSB of image channels.
    Returns the chi-square statistic.
    """
    pixels = list(image.getdata())
    freq_lsb_0 = 0
    freq_lsb_1 = 0
    freq_lsb_pairs = {}

    # Count pairs of values differing in LSB bit
    for pixel in pixels:
        for val in pixel[:3]:  # R,G,B only
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

def is_stego_present(image, threshold=3.84):  # Chi-square critical value for 1 degree of freedom, 95% confidence
    chi_val = chi_square_lsb_test(image)
    # إذا كانت قيمة chi أقل من العتبة، احتمال وجود ستيجانو عالي
    return chi_val < threshold

def extract_message(image):
    width, height = image.size
    bits = ""

    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

    end_signal = '11111110'  # علامة نهاية الرسالة
    if end_signal not in bits:
        return None

    message = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if byte == end_signal:
            break
        try:
            message += chr(int(byte, 2))
        except:
            return None

    printable_chars = set(string.printable)
    if all(c in printable_chars for c in message):
        return message
    return None

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

    return jsonify({
        "hidden": hidden,
        "message": message
    })
