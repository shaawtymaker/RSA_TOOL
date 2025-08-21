import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random

# ---------------- RSA Functions ----------------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q, t = divmod(a, m)
        a, m = m, t
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime!")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return (e, n), (d, n)

def encrypt(public_key, plaintext):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext]

def decrypt(private_key, ciphertext):
    d, n = private_key
    try:
        return ''.join([chr(pow(char, d, n)) for char in ciphertext])
    except:
        return "[Decryption Error]"

# ---------------- GUI ----------------
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 RSA Encryption & Decryption Tool")
        self.root.geometry("800x600")
        self.root.configure(bg="#1e1e1e")

        self.public_key = None
        self.private_key = None

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("TButton", padding=6, font=("Arial", 10, "bold"))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.encryptor_tab = ttk.Frame(notebook)
        self.decrypter_tab = ttk.Frame(notebook)

        notebook.add(self.encryptor_tab, text="Encryptor")
        notebook.add(self.decrypter_tab, text="Decrypter")

        self.build_encryptor(self.encryptor_tab)
        self.build_decrypter(self.decrypter_tab)

    # ---------------- Encryptor Tab ----------------
    def build_encryptor(self, tab):
        ttk.Label(tab, text="RSA Encryptor", font=("Arial", 16, "bold"), foreground="#00ffcc").pack(pady=10)

        frame = ttk.Frame(tab)
        frame.pack(pady=5)

        ttk.Label(frame, text="Prime p:").grid(row=0, column=0, padx=5, pady=5)
        self.p_entry = tk.Entry(frame, width=10)
        self.p_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Prime q:").grid(row=0, column=2, padx=5, pady=5)
        self.q_entry = tk.Entry(frame, width=10)
        self.q_entry.grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(frame, text="🔑 Generate Keys", command=self.generate_keys).grid(row=0, column=4, padx=5)

        # Key Display
        self.key_display = tk.Text(tab, height=4, width=80, bg="#2d2d2d", fg="yellow", insertbackground="white")
        self.key_display.pack(pady=10)

        # Key Ops
        key_ops = ttk.Frame(tab)
        key_ops.pack(pady=5)
        ttk.Button(key_ops, text="📋 Copy Keys", command=self.copy_keys).pack(side="left", padx=5)
        ttk.Button(key_ops, text="💾 Export Keys", command=self.export_keys).pack(side="left", padx=5)
        ttk.Button(key_ops, text="📂 Import Keys", command=self.import_keys).pack(side="left", padx=5)

        # Plaintext
        ttk.Label(tab, text="Enter Message:").pack()
        self.message_entry = tk.Text(tab, height=4, width=80, bg="#2d2d2d", fg="white", insertbackground="white")
        self.message_entry.pack(pady=5)

        ttk.Button(tab, text="🔒 Encrypt", command=self.encrypt_message).pack(pady=10)

        ttk.Label(tab, text="Encrypted Message:").pack()
        self.encrypted_output = tk.Text(tab, height=4, width=80, bg="#2d2d2d", fg="cyan", insertbackground="white")
        self.encrypted_output.pack(pady=5)

        ttk.Button(tab, text="📋 Copy Encrypted", command=self.copy_encrypted).pack(pady=5)

        # File ops
        file_frame = ttk.Frame(tab)
        file_frame.pack(pady=10)
        ttk.Button(file_frame, text="📂 Encrypt File", command=self.encrypt_file).pack(side="left", padx=5)
        ttk.Button(file_frame, text="📂 Decrypt File", command=self.decrypt_file).pack(side="left", padx=5)

    # ---------------- Decrypter Tab ----------------
    def build_decrypter(self, tab):
        ttk.Label(tab, text="Standalone Decrypter", font=("Arial", 16, "bold"), foreground="#ffcc00").pack(pady=10)

        key_frame = ttk.Frame(tab)
        key_frame.pack(pady=5)

        ttk.Label(key_frame, text="Enter Private Key (format: (d, n))").pack(side="left", padx=5)
        self.key_entry = tk.Entry(key_frame, width=50, bg="#2d2d2d", fg="white", insertbackground="white")
        self.key_entry.pack(side="left", padx=5)

        ttk.Button(key_frame, text="📂 Import Keys", command=self.import_keys_decrypter).pack(side="left", padx=5)

        ttk.Label(tab, text="Enter Ciphertext (list of numbers)").pack(pady=5)
        self.cipher_entry = tk.Text(tab, height=5, width=80, bg="#2d2d2d", fg="cyan", insertbackground="white")
        self.cipher_entry.pack(pady=5)

        ttk.Button(tab, text="🔓 Decrypt", command=self.standalone_decrypt).pack(pady=10)

        ttk.Label(tab, text="Decrypted Message:").pack()
        self.standalone_output = tk.Text(tab, height=4, width=80, bg="#2d2d2d", fg="yellow", insertbackground="white")
        self.standalone_output.pack(pady=5)

    # ---------------- Encryptor Functions ----------------
    def generate_keys(self):
        try:
            p = int(self.p_entry.get())
            q = int(self.q_entry.get())
            self.public_key, self.private_key = generate_keypair(p, q)
            self.key_display.delete("1.0", tk.END)
            self.key_display.insert(tk.END, f"Public Key: {self.public_key}\nPrivate Key: {self.private_key}")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid primes!\n{e}")

    def encrypt_message(self):
        if not self.public_key:
            messagebox.showerror("Error", "Generate or import keys first!")
            return
        plaintext = self.message_entry.get("1.0", tk.END).strip()
        if not plaintext:
            return
        encrypted = encrypt(self.public_key, plaintext)
        self.encrypted_output.delete("1.0", tk.END)
        self.encrypted_output.insert(tk.END, str(encrypted))

    def copy_keys(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.key_display.get("1.0", tk.END).strip())
        messagebox.showinfo("Copied", "Keys copied to clipboard!")

    def copy_encrypted(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.encrypted_output.get("1.0", tk.END).strip())
        messagebox.showinfo("Copied", "Encrypted message copied!")

    def export_keys(self):
        if not (self.public_key and self.private_key):
            messagebox.showerror("Error", "No keys to export!")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(f"Public Key: {self.public_key}\nPrivate Key: {self.private_key}")
            messagebox.showinfo("Exported", "Keys exported successfully!")

    def import_keys(self):
        file_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.key_display.delete("1.0", tk.END)
            self.key_display.insert("1.0", content)

            # Try parsing keys
            lines = content.splitlines()
            self.public_key = eval(lines[0].split(":", 1)[1].strip())
            self.private_key = eval(lines[1].split(":", 1)[1].strip())
            messagebox.showinfo("Imported", "Keys imported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import keys!\n{e}")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File")
        if not file_path:
            return
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
        if not file_path:
            return
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

    def import_keys_decrypter(self):
        file_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                key_data = f.read().strip()
            # Parse private key only
            if "Private Key" in key_data:
                private_key = eval(key_data.split("Private Key:", 1)[1].strip())
            else:
                private_key = eval(key_data.strip())
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, str(private_key))
            messagebox.showinfo("Imported", "Private key imported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import key!\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
