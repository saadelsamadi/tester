from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)

def analyze_lsb_entropy(image, threshold=0.48):
    """
    يحلل توزيع LSB في Red channel.
    لو التوزيع قريب جدًا من 50% => احتمال Steganography.
    threshold: أقصى انحراف مقبول من 0.5.
    """
    width, height = image.size
    lsb_list = []

    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            lsb_list.append(r & 1)

    zeros = lsb_list.count(0)
    ones = lsb_list.count(1)
    total = len(lsb_list)

    if total == 0:
        return False, 0.0

    ratio = ones / total

    # لو النسبة قريبة جدًا من 50% => توزيع عشوائي => احتمال Steganography
    if abs(ratio - 0.5) < threshold:
        return True, ratio
    else:
        return False, ratio


@stegnography_bp.route('/stegnography', methods=['POST'])
def stegnography_route():
    save_path = None

    # استقبال الصورة
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
            file.save(save_path)
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

    # تحليل الصورة
    hidden, ratio = analyze_lsb_entropy(image)

    # حذف الصورة من السيرفر بعد التحليل (اختياري)
    if save_path and os.path.exists(save_path):
        os.remove(save_path)

    return jsonify({
        "hidden": hidden,
        "entropy_ratio": ratio,
        "message": "High LSB randomness detected (possible steganography)" if hidden else "No significant steganography patterns detected"
    })
