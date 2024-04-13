from flask import Flask, request
from cryptography.fernet import Fernet
import os.path
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
app = Flask(__name__)

cert_file = 'cert.pem'
key_file = 'key.pem'

# Here we generate key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)
print(cipher_suite)
# the upper part can be ignored

@app.route('/')
def index():
    return open('index.html').read()

@app.route('/send_encrypted_data', methods=['POST'])
def send_encrypted_data():
    data = request.form['data'].encode('utf-8')
    encrypted_data = cipher_suite.encrypt(data)
    # Here you can send the encrypted data wherever you want
    print("Encrypted data:", encrypted_data)
    return "Data sent successfully!"

@app.route('/secure')
def secure():
    return "This is a secure Flask server!"

if __name__ == '__main__':
    # Enable HTTPS by specifying the certificate and key files
    if os.path.exists(cert_file) and os.path.exists(key_file):
        app.run(ssl_context=(cert_file, key_file), debug=True)
    else:
        print("Certificate or key file not found. Generating new ones...")

        # Generate a new self-signed certificate and key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'localhost')
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Write the certificate and key to files
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print("Certificate and key files generated successfully.")

        # Run the Flask server with SSL context
        app.run(ssl_context=(cert_file, key_file), debug=True)
