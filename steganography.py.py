import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import numpy as np
from pathlib import Path
import platform
import os
import ctypes.wintypes  # Added for accurate Windows Desktop path

# macOS specific fix
if platform.system() == 'Darwin':
    os.environ['TK_SILENCE_DEPRECATION'] = '1'

def get_desktop_path():
    if platform.system() == "Windows":
        CSIDL_DESKTOP = 0
        SHGFP_TYPE_CURRENT = 0
        buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
        ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOP, None, SHGFP_TYPE_CURRENT, buf)
        return Path(buf.value)
    else:
        return Path.home() / "Desktop"

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password"

def encrypt_image(image_path, message, key):
    img = Image.open(image_path)
    if img.mode not in ["RGB", "RGBA"]:
        img = img.convert("RGB")
    pixels = np.array(img, dtype=np.uint8)

    message += "$$END$$"
    binary_message = "".join(f"{ord(char) ^ ord(key[i % len(key)]):08b}" for i, char in enumerate(message))
    
    if len(binary_message) > pixels.size:
        raise ValueError("Message is too large for this image.")
    
    flat_pixels = pixels.flatten().astype(np.int16)
    for i in range(len(binary_message)):
        flat_pixels[i] = (flat_pixels[i] & ~1) | int(binary_message[i])
    
    modified_pixels = np.clip(flat_pixels, 0, 255).astype(np.uint8)
    modified_pixels = modified_pixels.reshape(pixels.shape)
    return Image.fromarray(modified_pixels)

def decrypt_image(image_path, key):
    img = Image.open(image_path)
    pixels = np.array(img, dtype=np.uint8)
    
    binary_message = "".join(str(pixel & 1) for pixel in pixels.flatten())
    
    text = ""
    for i in range(0, len(binary_message), 8):
        byte = ''.join(binary_message[i:i+8])
        char = chr(int(byte, 2) ^ ord(key[i // 8 % len(key)]))
        text += char
        if "$$END$$" in text:
            return True, text.split("$$END$$")[0]
    return False, "Incorrect key or no message found."

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("800x600")
        self.root.configure(bg="#030315")
        self.configure_styles()
        self.show_login()

    def configure_styles(self):
        style = ttk.Style()
        style.configure("Cyber.TFrame", background="#0d0221")
        style.configure("Title.TLabel", font=("Orbitron", 24, "bold"), foreground="#ff2a6d", background="#0d0221")
        style.configure("Cyber.TButton", font=("Orbitron", 12, "bold"), foreground="black", background="#05d9e8")
        style.configure("Login.TLabel", font=("Orbitron", 14), foreground="#ff2a6d", background="#030315")
        style.configure("Login.TButton", font=("Orbitron", 12, "bold"), foreground="black", background="#05d9e8")

    def show_login(self):
        self.login_frame = ttk.Frame(self.root, style="Cyber.TFrame")
        self.login_frame.pack(expand=True)

        ttk.Label(self.login_frame, text="LOGIN", style="Title.TLabel").pack(pady=20)
        
        ttk.Label(self.login_frame, text="Username:", style="Login.TLabel").pack()
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack()
        
        ttk.Label(self.login_frame, text="Password:", style="Login.TLabel").pack()
        self.password_entry = ttk.Entry(self.login_frame, show='*')
        self.password_entry.pack()
        
        ttk.Button(self.login_frame, text="Login", style="Login.TButton", command=self.check_login).pack(pady=10)

    def check_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
            self.login_frame.destroy()
            self.create_widgets()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def create_widgets(self):
        frame = ttk.Frame(self.root, style="Cyber.TFrame")
        frame.pack(expand=True)

        ttk.Label(frame, text="STEGANOGRAPHY TOOL", style="Title.TLabel").pack(pady=10)
        
        ttk.Button(frame, text="🔐 ENCRYPT MESSAGE", style="Cyber.TButton", command=self.encrypt_ui).pack(pady=10)
        ttk.Button(frame, text="🔓 DECRYPT MESSAGE", style="Cyber.TButton", command=self.decrypt_ui).pack(pady=10)
    
    def encrypt_ui(self):
        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tiff;*.webp")])
        if not image_path:
            return
        
        message = simpledialog.askstring("Input", "Enter the secret message:")
        if not message:
            messagebox.showerror("Error", "Message is required.")
            return
        
        key = simpledialog.askstring("Input", "Enter the encryption key:", show='*')
        if not key:
            messagebox.showerror("Error", "Key is required.")
            return
        
        output_name = simpledialog.askstring("Input", "Enter output image name:")
        if not output_name:
            output_name = "encrypted"
        
        # Get real desktop path and make folder only once
        DESKTOP_PATH = get_desktop_path()
        HIDED_IMGS_PATH = DESKTOP_PATH / "hided_imgs"
        HIDED_IMGS_PATH.mkdir(exist_ok=True)

        output_path = HIDED_IMGS_PATH / f"{output_name}.png"
        
        try:
            encrypted_img = encrypt_image(image_path, message, key)
            encrypted_img.save(output_path, format="PNG")
            messagebox.showinfo("Success", f"Encrypted image saved as: {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def decrypt_ui(self):
        image_path = filedialog.askopenfilename(title="Select Encrypted Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tiff;*.webp")])
        if not image_path:
            return
        
        key = simpledialog.askstring("Input", "Enter the decryption key:", show='*')
        if not key:
            messagebox.showerror("Error", "Key is required.")
            return

        success, result = decrypt_image(image_path, key)
        
        if success:
            self.show_decrypted_message(result)
        else:
            messagebox.showerror("Error", result)

    def show_decrypted_message(self, result):
        self.decrypted_window = tk.Toplevel(self.root)
        self.decrypted_window.title("Decrypted Message")
        self.decrypted_window.geometry("400x200")
        self.decrypted_window.configure(bg="#030315")
        label = ttk.Label(self.decrypted_window, text=result, font=("Orbitron", 14), background="#0d0221", foreground="#ff2a6d")
        label.pack(expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
