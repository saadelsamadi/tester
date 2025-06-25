
from flask import Flask
from features.api import api_bp
import os
from features.blacklist import blacklist_bp
from features.checkattach import checkattach_bp
from features.full import full_bp
from features.fullapi import fullapi_bp
from features.header import header_bp
from features.spfdmarc import spfdmarc_bp
from features.ssltls import ssltls_bp
from features.sstegno import sstegno_bp
from features.stegnography import stegnography_bp
from features.urlcheck import urlcheck_bp
from features.whoise import whoise_bp
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.register_blueprint(api_bp)
app.register_blueprint(blacklist_bp)
app.register_blueprint(checkattach_bp)
app.register_blueprint(full_bp)
app.register_blueprint(fullapi_bp)
app.register_blueprint(header_bp)
app.register_blueprint(spfdmarc_bp)
app.register_blueprint(ssltls_bp)
app.register_blueprint(sstegno_bp)
app.register_blueprint(stegnography_bp)
app.register_blueprint(urlcheck_bp)
app.register_blueprint(whoise_bp)

@app.route('/')
def home():
    return {"message": "Unified API with all features is running!"}

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
