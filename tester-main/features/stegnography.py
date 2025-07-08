from flask import Blueprint, request, jsonify
from PIL import Image
import io
import base64
from flask_cors import CORS
import os
import string

stegnography_bp = Blueprint('stegnography', __name__)
CORS(stegnography_bp)

def chi_square_test(image):
    """
    اختبار Chi-Square لتوزيع LSB في الصورة
    كل ما كانت القيمة أقل => احتمال وجود ستجانو أعلى.
    العتبة الافتراضية 15000 (يمكن تعديلها حسب الحاجة).
    """
    pixels = list(image.getdata())

    freq = [0] * 256
    for pixel in pixels:
        for val in pixel[:3]:  # فقط R,G,B
            freq[val] += 1

    chi_square_total = 0
    for i in range(0, 256, 2):
        observed_0 = freq[i]
        observed_1 = freq[i + 1]
        expected = (observed_0 + observed_1) / 2

        if expected > 0:
            chi_square_total += ((observed_0 - expected) ** 2) / expected
            chi_square_total += ((observed_1 - expected) ** 2) / expected

    return chi_square_total

def is_stego_present(image, chi_threshold=15000):
    chi_value = chi_square_test(image)
    return chi_value < chi_threshold

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

    # تحقق أن الرسالة تحتوي على حروف قابلة للطباعة فقط
    printable_chars = set(string.printable)
    if all(c in printable_chars for c in message):
        return message
    return None

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
        message = extract_message_from_image(image)
        if message:
            hidden = True

    return jsonify({
        "hidden": hidden,
        "message": message
    })
