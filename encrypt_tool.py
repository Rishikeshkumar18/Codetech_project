import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Function to generate a key from a password using scrypt
def generate_key(password):
    salt = os.urandom(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)  # AES-256
    return key, salt

# Encrypt a file
def encrypt_file(file_path, password):
    try:
        # Generate AES key from password
        key, salt = generate_key(password)

        # Read file data
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Generate a random IV (Initialization Vector) for AES
        iv = get_random_bytes(16)

        # AES Encryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

        # Write encrypted data and salt/IV to output file
        encrypted_file = file_path + '.enc'
        with open(encrypted_file, 'wb') as file:
            file.write(salt)  # Write salt for key derivation
            file.write(iv)    # Write IV for AES
            file.write(encrypted_data)
        
        return encrypted_file
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
        return None

# Decrypt a file
def decrypt_file(file_path, password):
    try:
        # Read encrypted file data
        with open(file_path, 'rb') as file:
            salt = file.read(16)  # Read salt
            iv = file.read(16)    # Read IV
            encrypted_data = file.read()

        # Generate AES key from password and salt
        key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)

        # AES Decryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Write decrypted data to output file
        decrypted_file = file_path[:-4]  # Remove .enc extension
        with open(decrypted_file, 'wb') as file:
            file.write(decrypted_data)

        return decrypted_file
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        return None

# Select a file to encrypt
def select_file_for_encryption():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        password = entry_password.get()
        if password:
            encrypted_file = encrypt_file(file_path, password)
            if encrypted_file:
                messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_file}")
        else:
            messagebox.showerror("Input Error", "Please enter a password.")

# Select a file to decrypt
def select_file_for_decryption():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        password = entry_password.get()
        if password:
            decrypted_file = decrypt_file(file_path, password)
            if decrypted_file:
                messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file}")
        else:
            messagebox.showerror("Input Error", "Please enter a password.")

# Setting up the Tkinter UI
root = tk.Tk()
root.title("AES-256 Encryption Tool")

# Dark-themed UI for hacker look
root.config(bg="#1c1c1c")

# Labels and Entry Widgets
label_password = tk.Label(root, text="Enter Password:", fg="white", bg="#1c1c1c")
label_password.grid(row=0, column=0, padx=10, pady=10)

entry_password = tk.Entry(root, show="*", fg="white", bg="#333333", insertbackground="white", width=30)
entry_password.grid(row=0, column=1, padx=10, pady=10)

# Encrypt Button
encrypt_button = tk.Button(root, text="Encrypt File", command=select_file_for_encryption, fg="white", bg="#00b33c")
encrypt_button.grid(row=1, column=0, columnspan=2, pady=10)

# Decrypt Button
decrypt_button = tk.Button(root, text="Decrypt File", command=select_file_for_decryption, fg="white", bg="#b30000")
decrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

# Running the Tkinter main loop
root.mainloop()
