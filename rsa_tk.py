import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random
from math import gcd

# ---------------- RSA Core ----------------
def is_prime(num):
    if num < 2: return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0: return False
    return True

def generate_large_prime():
    while True:
        num = random.randint(100, 300)  # demo size
        if is_prime(num): return num

def generate_keypair():
    p, q = generate_large_prime(), generate_large_prime()
    while q == p:
        q = generate_large_prime()
    n, phi = p * q, (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def encrypt(public_key, plaintext):
    e, n = public_key
    return [pow(ord(ch), e, n) for ch in plaintext]

def decrypt(private_key, ciphertext):
    d, n = private_key
    try:
        return ''.join([chr(pow(c, d, n)) for c in ciphertext])
    except:
        return "[Decryption Error]"


# ---------------- Main GUI ----------------
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 RSA Encryption & Decryption Suite")
        self.root.geometry("800x600")
        self.root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2d2d2d")
        style.configure("TLabel", background="#2d2d2d", foreground="white", font=("Arial", 11))
        style.configure("TButton", padding=6, font=("Arial", 10, "bold"), background="#444", foreground="white")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        # Tabs
        self.encryptor_tab = ttk.Frame(notebook)
        self.decrypter_tab = ttk.Frame(notebook)
        notebook.add(self.encryptor_tab, text="🔒 Encryptor")
        notebook.add(self.decrypter_tab, text="🔓 Decrypter")

        self.build_encryptor(self.encryptor_tab)
        self.build_decrypter(self.decrypter_tab)

    # ---------------- Encryptor Tab ----------------
    def build_encryptor(self, tab):
        # Generate keys
        self.public_key, self.private_key = generate_keypair()

        ttk.Label(tab, text="RSA Encryptor", font=("Arial", 16, "bold"), foreground="#00ffcc").pack(pady=10)

        key_frame = ttk.LabelFrame(tab, text="🔑 Keys", padding=10)
        key_frame.pack(fill="x", padx=10, pady=10)
        self.key_label = ttk.Label(key_frame, text=f"Public: {self.public_key}\nPrivate: {self.private_key}")
        self.key_label.pack(pady=5)

        ttk.Button(key_frame, text="🔄 Generate New Keys", command=self.generate_new_keys).pack()

        # Input
        input_frame = ttk.LabelFrame(tab, text="✍️ Enter Message", padding=10)
        input_frame.pack(fill="x", padx=10, pady=10)
        self.input_text = tk.Text(input_frame, height=4, width=80, bg="#1e1e1e", fg="white", insertbackground="white")
        self.input_text.pack()
        ttk.Button(input_frame, text="🔒 Encrypt Text", command=self.encrypt_message).pack(pady=5)

        # Encrypted Output
        enc_frame = ttk.LabelFrame(tab, text="📜 Encrypted", padding=10)
        enc_frame.pack(fill="x", padx=10, pady=10)
        self.encrypted_output = tk.Text(enc_frame, height=4, width=80, bg="#1e1e1e", fg="#00ffcc", insertbackground="white")
        self.encrypted_output.pack()
        ttk.Button(enc_frame, text="📋 Copy Encrypted", command=self.copy_encrypted).pack(pady=5)

        # Decrypted Output
        dec_frame = ttk.LabelFrame(tab, text="📜 Decrypted", padding=10)
        dec_frame.pack(fill="x", padx=10, pady=10)
        self.decrypted_output = tk.Text(dec_frame, height=4, width=80, bg="#1e1e1e", fg="#ffcc00", insertbackground="white")
        self.decrypted_output.pack()
        ttk.Button(dec_frame, text="📋 Copy Decrypted", command=self.copy_decrypted).pack(pady=5)

        # File Ops
        file_frame = ttk.LabelFrame(tab, text="📂 File Operations", padding=10)
        file_frame.pack(fill="x", padx=10, pady=10)
        ttk.Button(file_frame, text="📂 Encrypt File", command=self.encrypt_file).pack(side="left", padx=5)
        ttk.Button(file_frame, text="📂 Decrypt File", command=self.decrypt_file).pack(side="left", padx=5)

    # ---------------- Decrypter Tab ----------------
    def build_decrypter(self, tab):
        ttk.Label(tab, text="Standalone Decrypter", font=("Arial", 16, "bold"), foreground="#ffcc00").pack(pady=10)

        ttk.Label(tab, text="Enter Private Key (format: (d, n))").pack(pady=5)
        self.key_entry = tk.Entry(tab, width=70, bg="#2d2d2d", fg="white", insertbackground="white")
        self.key_entry.pack(pady=5)

        ttk.Label(tab, text="Enter Ciphertext (list of numbers)").pack(pady=5)
        self.cipher_entry = tk.Text(tab, height=5, width=80, bg="#2d2d2d", fg="cyan", insertbackground="white")
        self.cipher_entry.pack(pady=5)

        ttk.Button(tab, text="🔓 Decrypt", command=self.standalone_decrypt).pack(pady=10)

        ttk.Label(tab, text="Decrypted Message:").pack()
        self.standalone_output = tk.Text(tab, height=4, width=80, bg="#2d2d2d", fg="yellow", insertbackground="white")
        self.standalone_output.pack(pady=5)

    # ---------------- Encryptor Functions ----------------
    def generate_new_keys(self):
        self.public_key, self.private_key = generate_keypair()
        self.key_label.config(text=f"Public: {self.public_key}\nPrivate: {self.private_key}")
        messagebox.showinfo("Keys", "New keys generated!")

    def encrypt_message(self):
        plaintext = self.input_text.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Enter a message first!")
            return
        self.encrypted = encrypt(self.public_key, plaintext)
        self.encrypted_output.delete("1.0", tk.END)
        self.encrypted_output.insert(tk.END, str(self.encrypted))
        # auto-decrypt for testing
        decrypted = decrypt(self.private_key, self.encrypted)
        self.decrypted_output.delete("1.0", tk.END)
        self.decrypted_output.insert(tk.END, decrypted)

    def copy_encrypted(self):
        text = self.encrypted_output.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Encrypted text copied!")

    def copy_decrypted(self):
        text = self.decrypted_output.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Decrypted text copied!")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File")
        if not file_path: return
        with open(file_path, "r", encoding="utf-8") as f:
            data = f.read()
        encrypted_data = encrypt(self.public_key, data)
        save_path = filedialog.asksaveasfilename(defaultextension=".rsa", filetypes=[("RSA Encrypted", "*.rsa")])
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(str(encrypted_data))
            messagebox.showinfo("Success", f"File saved: {save_path}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("RSA Encrypted", "*.rsa")])
        if not file_path: return
        with open(file_path, "r", encoding="utf-8") as f:
            encrypted_data = eval(f.read())
        decrypted_data = decrypt(self.private_key, encrypted_data)
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", f"Decrypted file saved: {save_path}")

    # ---------------- Decrypter Functions ----------------
    def standalone_decrypt(self):
        try:
            private_key = eval(self.key_entry.get().strip())
            ciphertext = eval(self.cipher_entry.get("1.0", tk.END).strip())
            decrypted = decrypt(private_key, ciphertext)
            self.standalone_output.delete("1.0", tk.END)
            self.standalone_output.insert(tk.END, decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input!\n{e}")


# ---------------- Run ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
