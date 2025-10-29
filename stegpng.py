import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

SALT_SIZE = 16
IV_SIZE = AES.block_size
KEY_SIZE = 32

BG_COLOR = "#2b2b2b"
TEXT_COLOR = "#f0f0f0"
ACCENT_COLOR = "#00FF00"
WIDGET_BG_COLOR = "#3c3f41"
WIDGET_FG_COLOR = "#00FF00"
BUTTON_BG_COLOR = "#444444"
BUTTON_FG_COLOR = "#00FF00"


class StegPNG:
    def __init__(self, master):
        self.master = master
        master.title("StegPNG - Image Steganography")
        master.geometry("750x650")
        master.resizable(False, False)
        master.config(bg=BG_COLOR)

        self.image_path = None
        self.output_image_path = None

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".",
                        background=BG_COLOR,
                        foreground=TEXT_COLOR,
                        font=("Helvetica", 10))

        style.configure("TLabelframe",
                        background=BG_COLOR,
                        foreground=ACCENT_COLOR,
                        font=("Helvetica", 11, "bold"),
                        bordercolor=WIDGET_BG_COLOR)
        style.configure("TLabelframe.Label",
                        background=BG_COLOR,
                        foreground=ACCENT_COLOR)

        style.configure("TButton",
                        background=BUTTON_BG_COLOR,
                        foreground=BUTTON_FG_COLOR,
                        bordercolor=ACCENT_COLOR,
                        font=("Helvetica", 10, "bold"),
                        padding=5)
        style.map("TButton",
                  background=[('active', ACCENT_COLOR)],
                  foreground=[('active', 'black')])

        style.configure("TRadiobutton",
                        background=BG_COLOR,
                        foreground=TEXT_COLOR)
        style.map("TRadiobutton",
                  background=[('active', WIDGET_BG_COLOR)])

        style.configure("TEntry",
                        fieldbackground=WIDGET_BG_COLOR,
                        foreground=WIDGET_FG_COLOR,
                        insertcolor=ACCENT_COLOR)

        self.mode_frame = ttk.LabelFrame(master, text="Select Mode")
        self.mode_frame.pack(pady=10, padx=20, fill=tk.X)

        self.mode_var = tk.StringVar(value="hide")
        self.hide_radio = ttk.Radiobutton(self.mode_frame, text="Hide Message", variable=self.mode_var, value="hide",
                                          command=self.update_mode)
        self.hide_radio.pack(side=tk.LEFT, padx=10, pady=5)
        self.extract_radio = ttk.Radiobutton(self.mode_frame, text="Extract Message", variable=self.mode_var,
                                             value="extract", command=self.update_mode)
        self.extract_radio.pack(side=tk.LEFT, padx=10, pady=5)

        self.file_frame = ttk.LabelFrame(master, text="Image Selection")
        self.file_frame.pack(pady=10, padx=20, fill=tk.X)

        self.choose_image_button = ttk.Button(self.file_frame, text="Choose Cover Image (PNG recommended)",
                                              command=self.choose_image)
        self.choose_image_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.image_path_var = tk.StringVar(value="No image selected.")
        self.image_path_label = ttk.Label(self.file_frame, textvariable=self.image_path_var,
                                          font=("Consolas", 9, "italic"))
        self.image_path_label.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.message_frame = ttk.LabelFrame(master, text="Message")
        self.message_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        self.message_label = ttk.Label(self.message_frame, text="Message to Hide:")
        self.message_label.pack(anchor="w", padx=5, pady=2)

        self.message_text = scrolledtext.ScrolledText(
            self.message_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            height=8,
            bg=WIDGET_BG_COLOR,
            fg=WIDGET_FG_COLOR,
            insertbackground=ACCENT_COLOR
        )
        self.message_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.password_frame = ttk.LabelFrame(master, text="Password for Encryption/Decryption")
        self.password_frame.pack(pady=10, padx=20, fill=tk.X)

        self.password_label = ttk.Label(self.password_frame, text="Password:")
        self.password_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.password_frame, show="*", width=40)
        self.password_entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill=tk.X)

        style.configure("Accent.TButton",
                        background=ACCENT_COLOR,
                        foreground="black",
                        font=("Helvetica", 12, "bold"))
        style.map("Accent.TButton",
                  background=[('active', "#33FF33")],
                  foreground=[('active', 'black')])

        self.action_button = ttk.Button(master, text="Hide Message", command=self.perform_action,
                                        style="Accent.TButton")
        self.action_button.pack(pady=15)

        style.configure("Status.TLabel",
                        background="#222222",
                        foreground=ACCENT_COLOR,
                        relief=tk.SUNKEN,
                        font=("Consolas", 9))
        self.status_bar = ttk.Label(master, text="Ready.", relief=tk.SUNKEN, anchor="w", style="Status.TLabel")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.update_mode()

    def update_mode(self):
        mode = self.mode_var.get()

        self.message_text.config(state=tk.NORMAL)
        self.message_text.delete(1.0, tk.END)
        self.password_entry.delete(0, tk.END)

        if mode == "hide":
            self.message_label.config(text="Message to Hide:")
            self.action_button.config(text="Hide Message", command=self.perform_action)
            self.message_text.config(state=tk.NORMAL)
        elif mode == "extract":
            self.message_label.config(text="Extracted Message:")
            self.action_button.config(text="Extract Message", command=self.perform_action)
            self.message_text.config(state=tk.DISABLED)

        self.status_bar.config(text=f"Mode: {mode.capitalize()} Message.")

    def choose_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[
                ("PNG Image", "*.png"),
                ("All Image Files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            if self.mode_var.get() == "hide" and not file_path.lower().endswith(".png"):
                messagebox.showwarning("Warning",
                                       "PNG images are highly recommended for hiding messages due to their lossless compression. Using other formats may result in data loss.")
            self.image_path = file_path
            self.image_path_var.set(os.path.basename(file_path))
            self.status_bar.config(text=f"Image selected: {os.path.basename(file_path)}")
        else:
            self.image_path = None
            self.image_path_var.set("No image selected.")
            self.status_bar.config(text="Image selection cancelled.")

    def perform_action(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image file first.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        mode = self.mode_var.get()
        if mode == "hide":
            message_to_hide = self.message_text.get(1.0, tk.END).strip()
            if not message_to_hide:
                messagebox.showerror("Error", "Please enter a message to hide.")
                return
            self.hide_message(message_to_hide, password)
        elif mode == "extract":
            self.extract_message(password)

    def encrypt_message(self, message, password):
        try:
            salt = get_random_bytes(SALT_SIZE)
            key = PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=100000)
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext_bytes = cipher.encrypt(self._pad_message(message.encode('utf-8')))
            return salt + cipher.iv + ciphertext_bytes
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt message: {e}")
            return None

    def decrypt_message(self, encrypted_data, password):
        try:
            if len(encrypted_data) < (SALT_SIZE + IV_SIZE):
                raise ValueError("Encrypted data is too short to contain salt and IV.")

            salt = encrypted_data[:SALT_SIZE]
            iv = encrypted_data[SALT_SIZE: SALT_SIZE + IV_SIZE]
            ciphertext_bytes = encrypted_data[SALT_SIZE + IV_SIZE:]

            key = PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=100000)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_bytes = self._unpad_message(cipher.decrypt(ciphertext_bytes))
            return decrypted_bytes.decode('utf-8')
        except (ValueError, KeyError):
            messagebox.showerror("Decryption Error", "Incorrect password or corrupted data.")
            return None
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt message: {e}")
            return None

    def _pad_message(self, message):
        pad_len = AES.block_size - (len(message) % AES.block_size)
        return message + bytes([pad_len]) * pad_len

    def _unpad_message(self, message):
        pad_len = message[-1]
        if pad_len > AES.block_size:
            raise ValueError("Invalid padding detected.")
        return message[:-pad_len]

    def _bytes_to_bits(self, data_bytes):
        bits = ""
        for byte in data_bytes:
            bits += bin(byte)[2:].zfill(8)
        return bits

    def _bits_to_bytes(self, bits_string):
        data_bytes = bytearray()
        for i in range(0, len(bits_string), 8):
            byte_str = bits_string[i:i + 8]
            if len(byte_str) < 8:
                continue
            data_bytes.append(int(byte_str, 2))
        return bytes(data_bytes)

    def hide_message(self, message, password):
        try:
            img = Image.open(self.image_path).convert("RGBA")
            width, height = img.size
            pixels = img.load()

            encrypted_message_bytes = self.encrypt_message(message, password)
            if encrypted_message_bytes is None:
                return

            msg_len_bytes = len(encrypted_message_bytes).to_bytes(4, 'big')
            data_to_hide = msg_len_bytes + encrypted_message_bytes

            bits_to_hide = self._bytes_to_bits(data_to_hide)
            data_len = len(bits_to_hide)

            max_bits = width * height * 3
            if data_len > max_bits:
                messagebox.showerror("Error",
                                     f"Message too large for image. Needs {data_len} bits, image can only hide {max_bits} bits.")
                return

            data_index = 0
            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]

                    if data_index < data_len:
                        r = (r & 0xFE) | int(bits_to_hide[data_index])
                        data_index += 1
                    if data_index < data_len:
                        g = (g & 0xFE) | int(bits_to_hide[data_index])
                        data_index += 1
                    if data_index < data_len:
                        b = (b & 0xFE) | int(bits_to_hide[data_index])
                        data_index += 1

                    pixels[x, y] = (r, g, b, a)

                    if data_index >= data_len:
                        break
                if data_index >= data_len:
                    break

            output_path = filedialog.asksaveasfilename(
                title="Save Stego Image As...",
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")]
            )
            if output_path:
                img.save(output_path)
                self.output_image_path = output_path
                messagebox.showinfo("Success", f"Message hidden successfully in:\n{os.path.basename(output_path)}")
                self.status_bar.config(text=f"Message hidden. Saved to: {os.path.basename(output_path)}")
            else:
                messagebox.showinfo("Info", "Stego image not saved.")


        except FileNotFoundError:
            messagebox.showerror("Error", "Image file not found.")
        except IOError:
            messagebox.showerror("Error", "Could not open or process image file. Ensure it's a valid image.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during hiding: {e}")

    def extract_message(self, password):
        try:
            img = Image.open(self.image_path).convert("RGBA")
            width, height = img.size
            pixels = img.load()

            extracted_bits = ""
            hidden_msg_len = 0
            total_bits_to_extract = 32

            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]

                    extracted_bits += bin(r)[-1]
                    extracted_bits += bin(g)[-1]
                    extracted_bits += bin(b)[-1]

                    if hidden_msg_len == 0 and len(extracted_bits) >= 32:
                        msg_len_bits_str = extracted_bits[:32]
                        msg_len_bytes = self._bits_to_bytes(msg_len_bits_str)

                        hidden_msg_len = int.from_bytes(msg_len_bytes, 'big')

                        total_bits_to_extract = 32 + (hidden_msg_len * 8)

                        max_bits = width * height * 3
                        if total_bits_to_extract > max_bits:
                            messagebox.showerror("Error",
                                                 "Image data is corrupted or does not contain a valid message. Declared length is too large.")
                            return

                    if hidden_msg_len > 0 and len(extracted_bits) >= total_bits_to_extract:
                        break

                if hidden_msg_len > 0 and len(extracted_bits) >= total_bits_to_extract:
                    break

            if hidden_msg_len == 0 or len(extracted_bits) < total_bits_to_extract:
                messagebox.showerror("Error",
                                     "Could not find a complete hidden message. File may be wrong or corrupted.")
                return

            encrypted_message_bits = extracted_bits[32: total_bits_to_extract]
            encrypted_message_bytes = self._bits_to_bytes(encrypted_message_bits)

            decrypted_message = self.decrypt_message(encrypted_message_bytes, password)
            if decrypted_message is None:
                return

            self.message_text.config(state=tk.NORMAL)
            self.message_text.delete(1.0, tk.END)
            self.message_text.insert(tk.END, decrypted_message)
            self.message_text.config(state=tk.DISABLED)
            messagebox.showinfo("Success", "Message extracted and decrypted successfully!")
            self.status_bar.config(text="Message extracted successfully.")


        except FileNotFoundError:
            messagebox.showerror("Error", "Image file not found.")
        except IOError:
            messagebox.showerror("Error",
                                 "Could not open or process image file. Ensure it's a valid image or not corrupted.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during extraction: {e}")


if __name__ == "__main__":
    try:
        from Crypto.Cipher import AES
    except ImportError:
        messagebox.showerror(
            "Missing Libraries",
            "Required libraries are not installed.\n"
            "Please install them using:\npip install pycryptodome pillow"
        )
        exit()

    root = tk.Tk()
    app = StegPNG(root)
    root.mainloop()
