#!Users/guilhermecaetano/opt/anaconda3/envs/aes_encrypt_gui/bin/python

# When encypting files with this program, some AES encryption parameter choices are made by default. These exact same
# parameters are also needed for decryption, so it's advisable to have a backup of this python file to ensure that the
# correct decryption parameters will be available when needed.

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

# You can choose your own salt
salt_hex: str = '9d5907c8be1520e38192821d1dcd0c4d' # 32-digit hexadecimal

salt_bytes: bytes = bytes.fromhex(salt_hex)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Encrypt, Decrypt, Keygen")

        self.password: tk.StringVar = tk.StringVar()
        self.file_path: str = ""

        self.create_widgets()

    def create_widgets(self) -> None:
        #Password input:
        self.password_label: ttk.Label = ttk.Label(self, text="Enter password to encrypt/decrypt:")
        self.password_label.grid(column=0, row=0)
        self.password_entry: ttk.Entry = ttk.Entry(self, textvariable=self.password)
        self.password_entry.grid(column=0, row=1)
        self.grid_rowconfigure(2, minsize=20)

        #Encrypt/decrypt selection:
        self.choose_encrypt: ttk.Label = ttk.Label(self, text="Select file to encrypt or decrypt:")
        self.choose_encrypt.grid(column=0, row=3)
        self.btn_select_file_encrypt: ttk.Button = ttk.Button(self, text="Open", command=self.select_file)
        self.btn_select_file_encrypt.grid(column=0, row=4)
        self.chosen_file_name: ttk.Label = ttk.Label(self, text="No files selected")
        self.chosen_file_name.grid(column=0, row=5)
        self.grid_rowconfigure(6, minsize=20)

        #Action buttonsf
        self.btn_encrypt: ttk.Button = ttk.Button(self, text="Encrypt", command=self.encrypt_file)
        self.btn_encrypt.grid(column=0,row=8)
        self.btn_decrypt: ttk.Button = ttk.Button(self, text="Decrypt", command=self.decrypt_file)
        self.btn_decrypt.grid(column=0,row=9)

    def select_file(self) -> None:
        self.file_path: str = filedialog.askopenfilename()
        self.chosen_file_name['text'] = self.file_path
        return
            
    def generate_kdf(self, pwd: str) -> bytes:
        if len(salt_hex) != 32:
            messagebox.showerror("Invalid input","Error: Wrong Salt Length") #type: ignore
            return b'\xa0' # byte code for error
        
        if pwd == "":
            messagebox.showerror("Invalid input","Error: Invalid Password") #type: ignore
            return b'\xa0' # byte code for error
        
        return PBKDF2(pwd, salt_bytes, dkLen=32, count=100000, hmac_hash_module=SHA512)

    def encrypt_file(self) -> None:
        pbkdf2_key: bytes = self.generate_kdf(self.password.get())
        if pbkdf2_key == b'\xa0': # error handled by generate_kdf function
            return
        if self.file_path == "":
            messagebox.showerror("Invalid input","Error: No file selected") #type: ignore
            return
        
        with open(self.file_path, 'rb') as f:
            file_data: bytes = f.read()

        cipher = AES.new(pbkdf2_key, AES.MODE_EAX) # type: ignore
        ciphertext, tag = cipher.encrypt_and_digest(file_data) # type: ignore

        # Opens a dialog asking the user to choose a file name and path for saving the encrypted file
        output_file_path = filedialog.asksaveasfilename(defaultextension=".aes",
                                                         filetypes=[("AES encrypted files", "*.aes")],
                                                         title="Save encrypted file as...")
        # Check if the user has selected a file path
        if output_file_path:  # Ensuring the user didn't cancel the dialog
            with open(output_file_path, 'wb') as f:
                f.write(cipher.nonce) # type: ignore
                f.write(tag) # type: ignore
                f.write(ciphertext) # type: ignore

            messagebox.showinfo("Success", "File encrypted successfully!") # type: ignore
            self.file_path = ""
            self.chosen_file_name['text'] = ""

        else:
            messagebox.showinfo("Cancelled", "File encryption cancelled.") # type: ignore

        return
    
    def decrypt_file(self) -> None:
        pbkdf2_key: bytes = self.generate_kdf(self.password.get())
        if pbkdf2_key == b'\xa0':
            return
        if self.file_path == "":
            messagebox.showerror("Invalid input","Error: No file selected") #type: ignore
            return
        
        with open(self.file_path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

        cipher = AES.new(pbkdf2_key, AES.MODE_EAX, nonce=nonce) #type: ignore
        try:
            data: str = cipher.decrypt_and_verify(ciphertext, tag) #type: ignore
            # Writing the decrypted data to a new file
            decrypted_file_path: str = self.file_path.rsplit('.aes', 1)[0] #
            with open(decrypted_file_path, 'wb') as df:
                df.write(data) # type: ignore
            messagebox.showinfo("Success", "File decrypted successfully!") # type: ignore
            self.file_path = ""
        except ValueError:
            messagebox.showerror("Error", "Decryption failed. The file may be corrupted or the key incorrect.") # type: ignore

        return

if __name__ == "__main__":
    app = App()
    app.mainloop()
