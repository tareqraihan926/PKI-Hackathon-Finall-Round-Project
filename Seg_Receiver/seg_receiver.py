from flask import Flask, request, jsonify  # Flask web framework and HTTP response helpers
import ssl  # For setting up HTTPS server
from cryptography.hazmat.primitives import hashes  # For SHA-256 hashing
from cryptography.hazmat.primitives.asymmetric import padding  # For RSA signature verification
from cryptography import x509  # For certificate parsing

app = Flask(__name__)  # Create Flask web app instance

def verify_signature(public_key, xml_data, signature_hex):
    try:
        signature = bytes.fromhex(signature_hex)  # Convert hex string to bytes
        # Verify using RSA-PSS and SHA-256
        public_key.verify(
            signature,
            xml_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

@app.route('/submit', methods=['POST'])
def receive_document():
    try:
        # Get the client certificate (passed by Flask SSL context, only available via reverse proxy or custom WSGI server)
        client_cert = request.environ.get('SSL_CLIENT_CERT')
        if not client_cert:
            return jsonify({"error": "Client certificate missing"}), 403

        cert = x509.load_pem_x509_certificate(client_cert.encode())  # Load the client certificate
        public_key = cert.public_key()  # Extract the public key from certificate

        # Parse JSON payload
        data = request.get_json()
        xml_data = data["xml"]
        signature_hex = data["signature"]

        # Verify the digital signature
        if not verify_signature(public_key, xml_data, signature_hex):
            return jsonify({"error": "Invalid signature"}), 403

        print("[SUCCESS] Document integrity verified.")
        print(f"Received Document:\n{xml_data}")
        return jsonify({"status": "Document accepted"}), 200

    except Exception as e:
        print(f"[ERROR] Processing failed: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('seg_receiver.crt', 'seg_receiver.key')  # Load receiver's certificate and key
    ssl_context.load_verify_locations('rootCA.crt')  # Trust the root CA
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # Enforce client certificate authentication (mTLS)
    app.run(ssl_context=ssl_context, host='0.0.0.0', port=8443)  # Start HTTPS server
