from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)

def lsb_distribution(image):
    width, height = image.size
    count_ones = 0
    count_zeros = 0

    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            for val in (r, g, b):
                if (val & 1) == 1:
                    count_ones += 1
                else:
                    count_zeros += 1

    total = count_ones + count_zeros
    if total == 0:
        return 0, 0
    ratio_ones = count_ones / total
    ratio_zeros = count_zeros / total

    return ratio_ones, ratio_zeros

def is_stego_present(image, threshold=0.05):
    ratio_ones, ratio_zeros = lsb_distribution(image)
    return abs(ratio_ones - ratio_zeros) < threshold

def extract_message_from_image(image):
    width, height = image.size
    bits = ""

    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

    end_signal = '11111110'
    if end_signal not in bits:
        return None

    message = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if byte == end_signal:
            break
        try:
            message += chr(int(byte, 2))
        except:
            return None

    return message

@stegnography_bp.route('/stegnography', methods=['POST'])
def stegnography_route():
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
        except:
            return jsonify({"hidden": False, "message": None}), 400

    elif request.is_json and 'image_base64' in request.json:
        try:
            base64_str = request.json['image_base64']
            if 'base64,' in base64_str:
                base64_str = base64_str.split('base64,')[1]

            image_data = base64.b64decode(base64_str)
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
        except:
            return jsonify({"hidden": False, "message": None}), 400
    else:
        return jsonify({"hidden": False, "message": None}), 400

    hidden = False
    message = None

    if is_stego_present(image):
        message = extract_message_from_image(image)
        if message:
            hidden = True

    return jsonify({
        "hidden": hidden,
        "message": message
    })
