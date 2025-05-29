from flask import Flask, request, jsonify
from flask_cors import CORS
from email import message_from_file
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
import socket
import ssl
import whois
from PIL import Image
import io
import base64
import cv2
import numpy as np
import os
from werkzeug.utils import secure_filename
app = Flask(__name__)
CORS(app)

# --------- API 1: Extract Email Headers ---------
@app.route('/extract-emailheader', methods=['POST'])
def extract_headers_api():
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    temp_path = "/tmp/temp_email.eml"
    file.save(temp_path)

    try:
        with open(temp_path, 'r') as email_file:
            msg = message_from_file(email_file)

        from_ = msg.get("From", "N/A")
        to = msg.get("To", "N/A")
        subject = msg.get("Subject", "N/A")
        date = msg.get("Date", "N/A")
        message_id = msg.get("Message-ID", "N/A")
        reply_to = msg.get("Reply-To", "N/A")

        if date != "N/A":
            try:
                date = parsedate_to_datetime(date).isoformat()
            except:
                pass

        result = {
            "from": from_,
            "to": to,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "reply_to": reply_to
        }

    except Exception as e:
        result = {"error": f"Error reading or parsing the email file: {e}"}

    os.remove(temp_path)
    return jsonify(result)

# --------- API 2: SSL/TLS Certificate Details ---------
def get_ssl_certificate_details(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'Unknown')
        issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
        valid_from = cert.get('notBefore', 'Unknown')
        valid_to = cert.get('notAfter', 'Unknown')

        return {
            'IssuedTo': issued_to,
            'Issuer': issuer,
            'ValidFrom': valid_from,
            'ValidTo': valid_to,
        }

    except Exception as e:
        return {"error": f"Unable to retrieve SSL/TLS certificate details - {str(e)}"}

@app.route('/ssl', methods=['POST'])
def ssl_certificate_api():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Invalid request. 'url' is required."}), 400

    url = data['url'].strip()
    if not url.startswith("https://"):
        url = "https://" + url

    cert_details = get_ssl_certificate_details(url)
    return jsonify(cert_details), 200

# --------- API 3: WHOIS Lookup ---------
@app.route('/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' field"}), 400

    domain = data['domain'].strip()
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": str(w.domain_name),
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"WHOIS lookup failed: {str(e)}"}), 500


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

@app.route('/stegnography', methods=['POST'])
def api_extract_message():
    try:
        if 'image' in request.files:
            file = request.files['image']
            if file.filename == '':
                return jsonify({"hidden": False, "message": None}), 400
            image = Image.open(io.BytesIO(file.read()))
        elif request.is_json and 'image_base64' in request.json:
            base64_str = request.json['image_base64']
            if 'base64,' in base64_str:
                base64_str = base64_str.split('base64,')[1]
            image_data = base64.b64decode(base64_str)
            image = Image.open(io.BytesIO(image_data))
        else:
            return jsonify({"hidden": False, "message": None}), 400
        hidden_message = extract_message_from_image(image)
        return jsonify({
            "hidden": hidden_message is not None,
            "message": hidden_message
        })
    except:
        return jsonify({"hidden": False, "message": None}), 400

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_hidden_message_from_lsb(video_path):
    cap = cv2.VideoCapture(video_path)
    hidden_message_bits = []

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        lsb_frame = np.bitwise_and(gray_frame, 1)

        for row in lsb_frame:
            for pixel in row:
                hidden_message_bits.append(pixel)

    cap.release()

    message_bytes = bytearray()
    for i in range(0, len(hidden_message_bits), 8):
        byte = hidden_message_bits[i:i+8]
        if len(byte) == 8:
            message_bytes.append(int(''.join(str(b) for b in byte), 2))

    try:
        hidden_message = message_bytes.decode('utf-8')
    except UnicodeDecodeError:
        hidden_message = None

    return hidden_message

@app.route('/vid_stegnography', methods=['POST'])
def detect_steganography():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        hidden_message = extract_hidden_message_from_lsb(filepath)
        os.remove(filepath)

        if hidden_message:
            return jsonify({'hidden': True, 'message': hidden_message})
        else:
            return jsonify({'hidden': False, 'message': "No hidden message detected in the video."})

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': str(e)}), 500

# --------- Run the App ---------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=port)
