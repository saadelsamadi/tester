from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os
from stegano import lsb

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)

@stegnography_bp.route('/stegnography', methods=['POST'])
def stegnography_route():
    save_path = None

    # استقبال الصورة من form-data أو base64
    if 'image' in request.files:
        file = request.files['image']
        if file.filename == '':
            return jsonify({
                "hidden": False,
                "message": "No image file provided."
            }), 400

        filename = file.filename
        save_path = os.path.join(os.getcwd(), filename)
        try:
            file.save(save_path)
            image = Image.open(save_path).convert("RGB")
        except Exception as e:
            return jsonify({
                "hidden": False,
                "message": "Failed to open image."
            }), 400

    elif request.is_json and 'image_base64' in request.json:
        try:
            base64_str = request.json['image_base64']
            if 'base64,' in base64_str:
                base64_str = base64_str.split('base64,')[1]

            image_data = base64.b64decode(base64_str)
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            save_path = os.path.join(os.getcwd(), "temp_image.png")
            image.save(save_path)
        except Exception as e:
            return jsonify({
                "hidden": False,
                "message": "Failed to decode base64 image."
            }), 400
    else:
        return jsonify({
            "hidden": False,
            "message": "No image data provided."
        }), 400

    # استخدام مكتبة stegano للكشف
    try:
        secret = lsb.reveal(save_path)
        if secret is not None:
            hidden = True
            message = "Hidden message detected in image."
        else:
            hidden = False
            message = "No hidden message detected."
    except Exception as e:
        hidden = False
        message = f"Error during steganography detection: {str(e)}"

    # حذف الصورة بعد الفحص
    if save_path and os.path.exists(save_path):
        os.remove(save_path)

    return jsonify({
        "hidden": hidden,
        "message": message
    })
