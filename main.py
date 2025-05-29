from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import io
import base64
from PIL import Image
from email import message_from_file
from email.utils import parsedate_to_datetime
import socket, ssl
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# === Email Header Extraction ===
def extract_email_headers(file_path):
    try:
        with open(file_path, 'r') as email_file:
            msg = message_from_file(email_file)
        from_ = msg.get("From", "N/A")
        to = msg.get("To", "N/A")
        subject = msg.get("Subject", "N/A")
        date = msg.get("Date", "N/A")
        message_id = msg.get("Message-ID", "N/A")
        reply_to = msg.get("Reply-To", "N/A")
        if date != "N/A":
            try: date = parsedate_to_datetime(date).isoformat()
            except: pass
        return {
            "from": from_, "to": to, "subject": subject,
            "date": date, "message_id": message_id, "reply_to": reply_to
        }
    except Exception as e:
        return {"error": str(e)}

@app.route('/extract-emailheader', methods=['POST'])
def extract_headers_api():
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    temp_path = "temp_email.eml"
    file.save(temp_path)
    result = extract_email_headers(temp_path)
    os.remove(temp_path)
    return jsonify(result)

# === SSL Certificate Info ===
def get_ssl_certificate_details(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'Unknown')
        issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
        return {
            'IssuedTo': issued_to,
            'Issuer': issuer,
            'ValidFrom': cert.get('notBefore', 'Unknown'),
            'ValidTo': cert.get('notAfter', 'Unknown')
        }
    except Exception as e:
        return {"error": str(e)}

@app.route('/ssl', methods=['POST'])
def ssl_certificate_api():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith("https://"):
        url = "https://" + url
    return jsonify(get_ssl_certificate_details(url))

# === WHOIS (Placeholder) ===
@app.route('/whois', methods=['POST'])
def whois_api():
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    return jsonify({"domain": domain, "info": "WHOIS info here"})  # Replace with actual logic

# === Steganography ===
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

# === Start App ===
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
