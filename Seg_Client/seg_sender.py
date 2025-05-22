import requests  # For sending HTTPS requests
from cryptography.hazmat.primitives import hashes  # For SHA-256 hashing
from cryptography.hazmat.primitives.asymmetric import padding  # For RSA PSS padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key  # To load PEM-format private key

def sign_document(private_key_path, xml_data):
    # Load the private key for signing from PEM file
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # Sign the XML data using RSA-PSS and SHA-256
    signature = private_key.sign(
        xml_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()  # Return the signature as a hex string

def send_document(xml_path):
    try:
        # Read the XML document to be sent
        with open(xml_path, 'r') as f:
            xml_data = f.read()

        # Digitally sign the XML
        signature_hex = sign_document("seg_sender.key", xml_data)

        # Send the XML and signature as a JSON payload over HTTPS with client certificate authentication
        response = requests.post(
            'https://localhost:8443/submit',
            json={"xml": xml_data, "signature": signature_hex},
            cert=('seg_sender.crt', 'seg_sender.key'),
            verify='rootCA.crt',  # Verify server certificate against root CA
            headers={'Content-Type': 'application/json'}
        )

        print(f"[SUCCESS] Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"[ERROR] Transmission Failed: {e}")

if __name__ == '__main__':
    send_document('document.xml')  # Start the process with document.xml as input
