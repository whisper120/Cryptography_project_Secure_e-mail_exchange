import tkinter as tk
from ECDH import generate_keypair, diffie_hellman
from RC6_in_OFB import *
import hashlib
import rsa


def encrypt_message(symmetric_key, plaintext, text_decrypt, private_key):
    global iv
    global signature
    iv = generate_iv()

    plaintext = plaintext.encode()
    ciphertext = rc6_ofb_encrypt(symmetric_key, iv, plaintext)
    print("Ciphertext:", ciphertext.hex())
    text_decrypt.delete("1.0", tk.END)
    text_decrypt.insert("1.0", ciphertext.hex())


    # Ensure proper encoding of the ciphertext
    signature = rsa.sign_message(ciphertext.hex(), private_key)
    print('Digital signature added')
    print('Signature (hex):', signature)


def decrypt_message(symmetric_key, ciphertext, text_decrypt, public_key):
    global iv
    global signature
    ciphertext = bytes.fromhex(ciphertext)
    decrypted_plaintext = rc6_ofb_decrypt(symmetric_key, iv, ciphertext)
    print("Decrypted plaintext:", decrypted_plaintext)
    text_decrypt.delete("1.0", tk.END)
    text_decrypt.insert("1.0", decrypted_plaintext.decode())

    verification = rsa.verify_signature(ciphertext.hex(), signature, public_key)
    print('Verification:', 'Signature verified' if verification else 'Signature Failed')


def generate_iv():
    return os.urandom(16)


def initialize_keys():
    public_key, private_key = rsa.generate_keypair(512)
    global encryption_key
    encryption_key1, encryption_key2 = generate_keypair()
    shared_secret = diffie_hellman(encryption_key1, encryption_key2)
    encryption_key = hashlib.sha256(shared_secret).digest()[:16]
    return public_key, private_key


def main():
    public_key, private_key = initialize_keys()
    global encryption_key

    root = tk.Tk()
    root.title("Simple Encrypt/Decrypt UI")

    label_send = tk.Label(root, text="Enter Text to Send:")
    label_send.grid(row=0, column=0, padx=10, pady=10)
    text_send = tk.Text(root, height=10, width=50)
    text_send.grid(row=1, column=0, padx=10, pady=10)
    label_decrypt = tk.Label(root, text="Received Text:")
    label_decrypt.grid(row=0, column=1, padx=10, pady=10)
    text_decrypt = tk.Text(root, height=10, width=50)
    text_decrypt.grid(row=1, column=1, padx=10, pady=10)

    button_decrypt = tk.Button(root, text="Decrypt", command=lambda: decrypt_message(encryption_key, text_decrypt.get("1.0", "end-1c"), text_decrypt, public_key))
    button_decrypt.grid(row=2, column=1, padx=10, pady=10)
    button_send = tk.Button(root, text="Send", command=lambda: encrypt_message(encryption_key, text_send.get("1.0", "end-1c"), text_decrypt, private_key))
    button_send.grid(row=2, column=0, padx=10, pady=10)

    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    root.mainloop()


if __name__ == "__main__":
    main()

iv = None
encryption_key = None
signature = None
