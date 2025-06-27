import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
from pyfiglet import Figlet
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# --- Crypto Core ---
def password_to_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_text(text, key):
    try:
        fernet = Fernet(key)
        return fernet.encrypt(text.encode())
    except Exception as e:
        return None

def decrypt_file_gui(file_path, password):
    try:
        with open(file_path, "rb") as ef:
            salt = ef.read(16)
            encrypted_data = ef.read()
        key = password_to_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode()
    except InvalidToken:
        return "❌ Decryption failed. Incorrect password or file corrupted."
    except Exception as e:
        return f"❌ Error: {e}"

def generate_ascii_signature(name):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    figlet = Figlet(font='slant')
    signature = figlet.renderText(f"{name}_{timestamp}")
    return signature, timestamp

# --- GUI Logic ---
def encrypt_action():
    name = name_entry.get()
    password = password_entry.get()

    if not name or not password:
        messagebox.showerror("Missing Info", "Name and Password are required!")
        return

    ascii_art, timestamp = generate_ascii_signature(name)
    salt = os.urandom(16)
    key = password_to_key(password, salt)
    encrypted = encrypt_text(ascii_art, key)

    if encrypted:
        # Save to fixed path
        output_dir = r"C:\Users\manis\OneDrive\Desktop\PROJECT\ASCII Signature Designer"
        os.makedirs(output_dir, exist_ok=True)
        file_name = f"encrypted_signature_{name}_{timestamp}.txt"
        file_path = os.path.join(output_dir, file_name)

        with open(file_path, "wb") as f:
            f.write(salt + encrypted)

        ascii_text_box.delete('1.0', tk.END)
        ascii_text_box.insert(tk.END, ascii_art)

        encrypted_text_box.delete('1.0', tk.END)
        encrypted_text_box.insert(tk.END, encrypted.decode())

        messagebox.showinfo("Success", f"Signature encrypted and saved at:\n{file_path}")
    else:
        messagebox.showerror("Encryption Failed", "Something went wrong during encryption.")

def decrypt_action():
    file_path = filedialog.askopenfilename(title="Select Encrypted Signature File")
    if not file_path:
        return

    password = simpledialog.askstring("Enter Password", "Enter the password used for encryption:", show="*")
    if not password:
        messagebox.showwarning("Cancelled", "Password is required for decryption.")
        return

    result = decrypt_file_gui(file_path, password)
    decrypted_text_box.delete('1.0', tk.END)
    decrypted_text_box.insert(tk.END, result)

# --- GUI Layout ---
root = tk.Tk()
root.title("ASCII Signature Encryptor/Decryptor")
root.geometry("850x700")
root.resizable(False, False)

tk.Label(root, text="Name:", font=('Arial', 12)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
name_entry = tk.Entry(root, width=40)
name_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Password:", font=('Arial', 12)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
password_entry = tk.Entry(root, width=40, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Button(root, text="🔐 Encrypt & Save Signature", command=encrypt_action, bg="#4CAF50", fg="white", width=30).grid(row=2, column=0, padx=10, pady=10)
tk.Button(root, text="🔓 Decrypt Signature", command=decrypt_action, bg="#2196F3", fg="white", width=30).grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="🎨 ASCII Signature Output", font=("Arial", 10, "bold")).grid(row=3, column=0, columnspan=2)
ascii_text_box = scrolledtext.ScrolledText(root, width=100, height=8, font=("Courier", 10))
ascii_text_box.grid(row=4, column=0, columnspan=2, padx=10)

tk.Label(root, text="🔒 Encrypted (base64)", font=("Arial", 10, "bold")).grid(row=5, column=0, columnspan=2)
encrypted_text_box = scrolledtext.ScrolledText(root, width=100, height=4)
encrypted_text_box.grid(row=6, column=0, columnspan=2, padx=10)

tk.Label(root, text="🖋️ Decrypted ASCII Output", font=("Arial", 10, "bold")).grid(row=7, column=0, columnspan=2)
decrypted_text_box = scrolledtext.ScrolledText(root, width=100, height=8, font=("Courier", 10))
decrypted_text_box.grid(row=8, column=0, columnspan=2, padx=10)

root.mainloop()
