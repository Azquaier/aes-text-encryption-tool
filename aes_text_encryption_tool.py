"""
AES Text Encryption Tool

This module provides a simple Flask web application that allows users
to encrypt and decrypt text using AES encryption in CBC mode. A SHA-256
hash of the password is used as the key. Padding is applied to ensure
the plaintext fits the block size requirements of AES.
"""

from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

def pad(data):
    """
    Pad the input data to be a multiple of AES block size.

    Uses a PKCS#7-like padding scheme by appending bytes, where each
    byte's value represents the number of padding bytes added.

    Args:
        data (bytes): The data to pad.

    Returns:
        bytes: The padded data.
    """
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """
    Remove padding from the data.

    The function reads the value of the last byte to determine the
    length of the padding and then removes it.

    Args:
        data (bytes): The padded data.

    Returns:
        bytes: The original unpadded data.
    """
    pad_len = data[-1]
    return data[:-pad_len]

def get_key(password):
    """
    Generate a 256-bit AES key from a password using SHA-256.

    Args:
        password (str): The password string.

    Returns:
        bytes: A 32-byte key derived from the password.
    """
    return SHA256.new(password.encode()).digest()

def encrypt_text(plaintext, password):
    """
    Encrypt plaintext using AES encryption in CBC mode.

    The plaintext is encoded, padded, and encrypted. The IV is
    randomly generated and prepended to the encrypted data, which is then
    encoded using Base64.

    Args:
        plaintext (str): The text to encrypt.
        password (str): The encryption password.

    Returns:
        str: The Base64 encoded string containing the IV and ciphertext.
    """
    key = get_key(password)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext.encode())
    encrypted_bytes = cipher.encrypt(padded_text)
    # Concatenate IV and ciphertext, then encode to Base64.
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

def decrypt_text(ciphertext, password):
    """
    Decrypt ciphertext using AES decryption in CBC mode.

    The function decodes the Base64 input, extracts the IV, and decrypts
    the message. Padding is then removed. In case of an error, an error
    message is returned.

    Args:
        ciphertext (str): The Base64 encoded ciphertext with the IV.
        password (str): The decryption password.

    Returns:
        str: The decrypted plaintext or an error message if decryption fails.
    """
    try:
        key = get_key(password)
        data = base64.b64decode(ciphertext)
        iv = data[:AES.block_size]
        encrypted_bytes = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        return unpad(decrypted_padded).decode('utf-8')
    except Exception as e:
        return f"Decryption error: {str(e)}"

@app.route("/", methods=["GET"])
def root():
    """
    Render the main HTML template for the tool.

    Returns:
        str: Rendered HTML template with an empty output text.
    """
    return render_template("aes-text-encryption-tool.html", output_text="")

@app.route("/aes-text-encryption-tool", methods=["GET", "POST"])
def mein():
    """
    Handle encryption and decryption requests.

    Based on the HTTP method and the submitted form, this route either
    renders the template with empty output (GET) or processes encryption/decryption
    (POST).

    Returns:
        str: Rendered HTML template with the encryption/decryption output.
    """
    output_text = ""
    if request.method == "POST":
        password = request.form.get("password")
        input_text = request.form.get("input-text")
        action = request.form.get("action")
        if password and input_text:
            if action == "encrypt":
                output_text = encrypt_text(input_text, password)
            elif action == "decrypt":
                output_text = decrypt_text(input_text, password)
    return render_template("aes-text-encryption-tool.html", output_text=output_text)

if __name__ == "__main__":
    app.run(debug=False)
