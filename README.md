# Secure Document Exchange System

A PKI-enabled secure document exchange solution developed for the Public Key Infrastructure (PKI) Hackathon 2025. This project demonstrates a real-world scenario of two government departments exchanging sensitive XML documents securely using mTLS and digital signatures.

---

## 🔍 Project Overview

In scenarios where direct communication between two ministries is not feasible due to network restrictions or security policies, secure gateways must be used. This system implements:

- `SEG-Sender`: Prepares and signs an XML document, then transmits it securely.
- `SEG-Receiver`: Accepts incoming documents, authenticates the sender, and verifies the document's digital signature.

---

## ✅ Key Features

| Feature | Description |
|--------|-------------|
| mTLS | Mutual TLS authentication using X.509 certificates. |
| Digital Signature | XML documents are signed using RSA-PSS and verified on the receiver side. |
| Certificate Infrastructure | Includes a custom root CA and certificates signed for each SEG. |

---

## 📁 Project Structure

```
.
├── document.xml            # Sample XML document
├── seg_sender.py           # Sender-side Python script
├── seg_receiver.py         # Receiver-side Flask server
├── rootCA.crt/.key         # Root CA certificate and private key
├── seg_sender.crt/.key     # Sender's certificate and private key
├── seg_receiver.crt/.key   # Receiver's certificate and private key
├── README.md               # Project documentation
```

---

## 🔐 Step-by-Step Setup Guide

### Step 1: Generate the Root CA
```bash
openssl req -x509 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt -days 365 -nodes -subj "/CN=SEG Root CA"
```

### Step 2: Generate SEG-Receiver Certificate

If using SANs, create a file `san.cnf` with:
```
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = SEG-Receiver

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
```

Then run:
```bash
openssl req -new -newkey rsa:4096 -nodes -keyout seg_receiver.key -out seg_receiver.csr -config san.cnf
openssl x509 -req -in seg_receiver.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out seg_receiver.crt -days 365 -extfile san.cnf -extensions v3_req
```

### Step 3: Generate SEG-Sender Certificate
```bash
openssl req -new -newkey rsa:4096 -nodes -keyout seg_sender.key -out seg_sender.csr -subj "/CN=SEG-Sender"
openssl x509 -req -in seg_sender.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out seg_sender.crt -days 365
```

---

## ✍️ XML Document Signing

- SEG-Sender signs the document using its private key (`seg_sender.key`)
- Signature is hex-encoded and sent with the document via HTTPS

---

## 🚀 Running the System

### 1. Start SEG-Receiver
```bash
python3 seg_receiver.py
```
Expected log:
```
[SUCCESS] Document integrity verified.
Received Document:
<CriticalDocument>...</CriticalDocument>
```

### 2. Send Document from SEG-Sender
```bash
python3 seg_sender.py
```
Expected output:
```
[SUCCESS] Status: 200, Response: {"status": "Document accepted"}
```

---

## 📄 Example Input XML

```xml
<CriticalDocument id="doc123">
  <SenderID>MINISTRY 1_SEG01</SenderID>
  <ReceiverID>MINISTRY 2_SEG01</ReceiverID>
  <TimestampForSignature>2025-08-14T12:00:00Z</TimestampForSignature>
  <Payload>
    <SensitiveData>Lunch party at Saturday</SensitiveData>
    <Instructions>Deliver by 0300.</Instructions>
  </Payload>
</CriticalDocument>
```

---

## 🧪 Tamper Detection
If the XML is modified after signing, the receiver will reject it:
```json
{"error": "Invalid signature"}
```

---

## ⚙️ Python Dependencies

Install with pip:
```bash
pip install flask cryptography requests
```

---

## 👨‍💼 Authors
- Developed by: [Your Name Here]
- For: Public Key Infrastructure Hackathon 2025

---

## 📄 License

MIT License
