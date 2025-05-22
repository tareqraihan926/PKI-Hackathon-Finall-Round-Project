import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def sign_document(private_key_path, xml_data):
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # Sign the XML data
    signature = private_key.sign(
        xml_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()  # Convert bytes to hex string

def send_document(xml_path):
    try:
        with open(xml_path, 'r') as f:
            xml_data = f.read()

        # Sign the XML
        signature_hex = sign_document("seg_sender.key", xml_data)

        # Send XML + signature as JSON
        response = requests.post(
            'https://localhost:8443/submit',  # or actual IP/hostname
            json={"xml": xml_data, "signature": signature_hex},
            cert=('seg_sender.crt', 'seg_sender.key'),
            verify='rootCA.crt',
            headers={'Content-Type': 'application/json'}
        )

        print(f"[SUCCESS] Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"[ERROR] Transmission Failed: {e}")

if __name__ == '__main__':
    send_document('document.xml')

