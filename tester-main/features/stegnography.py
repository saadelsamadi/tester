from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)
def extract_message_from_image(image):
    width, height = image.size
    bits = ""

    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            bits += str(r & 1)

    end_signal = '11111110'
    if end_signal not in bits:
        return None

    message = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if byte == end_signal:
            break
        message += chr(int(byte, 2))

    return message


@stegnography_bp.route('/stegnography', methods=['POST'])
def stegnography_route():
    if 'image' in request.files:
        file = request.files['image']
        if file.filename == '':
            return jsonify({
                "hidden": False,
                "message": None
            }), 400

        filename = file.filename
        save_path = os.path.join(os.getcwd(), filename)
        try:
            file.save(save_path)  # حفظ الصورة على السيرفر
            image = Image.open(save_path)
            image = image.convert("RGB")
        except:
            return jsonify({
                "hidden": False,
                "message": None
            }), 400

    elif request.is_json and 'image_base64' in request.json:
        try:
            base64_str = request.json['image_base64']
            if 'base64,' in base64_str:
                base64_str = base64_str.split('base64,')[1]

            image_data = base64.b64decode(base64_str)
            image = Image.open(io.BytesIO(image_data))
            image = image.convert("RGB")
        except:
            return jsonify({
                "hidden": False,
                "message": None
            }), 400
    else:
        return jsonify({
            "hidden": False,
            "message": None
        }), 400

    hidden_message = extract_message_from_image(image)

    return jsonify({
        "hidden": hidden_message is not None,
        "message": hidden_message if hidden_message else None
    })
