from flask import Flask, request, jsonify
from flask_cors import CORS
from email import message_from_file
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
import socket
import ssl
import os
import whois
from PIL import Image
import io
import base64
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
    """Extracts hidden message from an image using LSB steganography."""
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
    """
    Simplified API endpoint to check for hidden messages.

    Returns:
    {
        "hidden": boolean (true if message found),
        "message": string (extracted message if found, else null)
    }
    """
    if 'image' in request.files:
        file = request.files['image']
        if file.filename == '':
            return jsonify({
                "hidden": False,
                "message": None
            }), 400

        try:
            image = Image.open(io.BytesIO(file.read()))
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


# --------- Run the App ---------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=port)
