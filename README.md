# AES Text Encryption Tool

A simple Flask web application that provides AES-based text encryption and decryption. It uses the PyCryptodome library to securely handle cryptographic operations with AES in CBC mode and SHA-256 for key derivation.
[→ Live Demo](https://azquaier.xyz/aes-text-encryption-tool)

## Features

- **Encrypt Text:** Securely encrypt input text using a provided password.
- **Decrypt Text:** Decrypt previously encrypted text with the same password.
- **Web Interface:** Simple HTML-based form for easy use.

## Requirements

- Python 3.x
- [Flask](https://flask.palletsprojects.com/)
- [PyCryptodome](https://pycryptodome.readthedocs.io/)

## Installation

Install the necessary dependencies using pip:

```bash
pip install flask pycryptodome
```

## Running the Application

Start the Flask app by running:

```bash
python aes_text_encryption_tool.py
```

By default, the app is accessible at [http://127.0.0.1:5000](http://127.0.0.1:5000).
