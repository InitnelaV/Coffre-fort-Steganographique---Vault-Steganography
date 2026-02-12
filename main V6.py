import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import hashlib
import base64
import json
import random
import string
import re

# Partie Crypto - Fonctions: Derivation - Encryptage - decryptage

def derive_key(password):
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_data(data_str, password):
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(data_str.encode())

def decrypt_data(data_bytes, password):
    key = derive_key(password)
    f = Fernet(key)
    return f.decrypt(data_bytes).decode()


# LSB (Bit de poids faible) Variable du End marker + Fonctions: Texte==>Binaire - Binaire==>Octets - Encodage - Decodage

END_MARKER = '1111111111111110'

def text_to_binary(message_bytes):
    return ''.join(format(byte, '08b') for byte in message_bytes)

def binary_to_bytes(binary):
    bytes_data = bytearray()
    for i in range(0, len(binary), 8):
        bytes_data.append(int(binary[i:i+8], 2))
    return bytes(bytes_data)

def encode_lsb(image_path, output_path, message_bytes):
    img = Image.open(image_path)

    # Correction mode image RGB / RGBA après encode
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    if img.mode == "RGBA":
        img = img.convert("RGB")

    pixels = img.load()

    binary = text_to_binary(message_bytes) + END_MARKER
    data_index = 0

    max_capacity = img.width * img.height * 3
    if len(binary) > max_capacity:
        raise ValueError("Image trop petite pour contenir les données.")

    for y in range(img.height):
        for x in range(img.width):
            if data_index >= len(binary):
                img.save(output_path)
                return output_path

            r, g, b = pixels[x, y]

            if data_index < len(binary):
                r = (r & ~1) | int(binary[data_index])
                data_index += 1
            if data_index < len(binary):
                g = (g & ~1) | int(binary[data_index])
                data_index += 1
            if data_index < len(binary):
                b = (b & ~1) | int(binary[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

    img.save(output_path)
    return output_path

def decode_lsb(image_path):
    img = Image.open(image_path)

    # Correction mode image RGB / RGBA après decode
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    if img.mode == "RGBA":
        img = img.convert("RGB")

    pixels = img.load()
    binary = ""

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)

    end_index = binary.find(END_MARKER)
    if end_index != -1:
        binary = binary[:end_index]
    else:
        return b""

    return binary_to_bytes(binary)

# GUI (Interface graphique user) Window scroll - boutons et cellules :
# Entry - URL - Log - MDP - Check MDP - Generation MDP - Copy MDP - Master - Visu MDP - Encode - Load + decode - List - result

class VaultGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Coffre-Fort Stéganographique")
        self.root.geometry("585x600")

        self.image_path = None
        self.vault_data = {}
        self.img_preview = None

        # Structure
        self.canvas_main = tk.Canvas(root)
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.canvas_main.yview)
        self.scrollable_frame = tk.Frame(self.canvas_main)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas_main.configure(
                scrollregion=self.canvas_main.bbox("all")
            )
        )

        self.canvas_main.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas_main.configure(yscrollcommand=self.scrollbar.set)

        self.canvas_main.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.canvas_main.bind_all("<MouseWheel>", self._on_mousewheel)

        # Widgets ( boutons, champs, scrolling)

        tk.Button(self.scrollable_frame, text="Sélectionner image du coffre", command=self.select_image).pack(pady=5)

        self.label_image = tk.Label(self.scrollable_frame, text="Aucune image sélectionnée")
        self.label_image.pack()

        self.preview_canvas = tk.Canvas(self.scrollable_frame, width=400, height=300, bg="grey")
        self.preview_canvas.pack(pady=5)

        tk.Label(self.scrollable_frame, text="Nom de l’entrée :").pack()
        self.entry_name = tk.Entry(self.scrollable_frame, width=50)
        self.entry_name.pack()

        tk.Label(self.scrollable_frame, text="URL :").pack()
        self.entry_url = tk.Entry(self.scrollable_frame, width=50)
        self.entry_url.pack()

        tk.Label(self.scrollable_frame, text="Login :").pack()
        self.entry_login = tk.Entry(self.scrollable_frame, width=50)
        self.entry_login.pack()

        tk.Label(self.scrollable_frame, text="Mot de passe :").pack()
        self.entry_mdp = tk.Entry(self.scrollable_frame, width=50, show="*")
        self.entry_mdp.pack()

        self.strength_label = tk.Label(self.scrollable_frame, text="Robustesse mot de passe : ")
        self.strength_label.pack()

        self.entry_mdp.bind("<KeyRelease>", self.on_password_change)

        tk.Button(self.scrollable_frame, text="Générer mot de passe", command=self.generate_password).pack(pady=3)
        tk.Button(self.scrollable_frame, text="Copier MDP", command=self.copy_password).pack(pady=3)

        tk.Label(self.scrollable_frame, text="Mot de passe maître :").pack()
        self.entry_password = tk.Entry(self.scrollable_frame, show="*")
        self.entry_password.pack()

        self.show_password_var = tk.BooleanVar()

        tk.Checkbutton(
            self.scrollable_frame,
            text="Afficher les mots de passe",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        ).pack(pady=5)

        tk.Button(self.scrollable_frame, text="Ajouter / Encoder", command=self.add_entry).pack(pady=5)
        tk.Button(self.scrollable_frame, text="Charger coffre", command=self.load_vault).pack(pady=5)
        tk.Button(self.scrollable_frame, text="Lister entrées", command=self.list_entries).pack(pady=5)
        tk.Button(self.scrollable_frame, text="Afficher sélection", command=self.decode_entry).pack(pady=5)

        tk.Label(self.scrollable_frame, text="Résultat :").pack()
        self.result_text = tk.Text(self.scrollable_frame, height=10, width=70)
        self.result_text.pack(pady=5)

    # Scroll molette - Fonction : Scroll

    def _on_mousewheel(self, event):
        self.canvas_main.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # Image preview - Fonctions Select pic - Show pic

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.bmp")])
        if path:
            self.image_path = path
            self.label_image.config(text=path)
            self.show_preview(path)

    def show_preview(self , path):
        try:
            img = Image.open(path)
            # Conversion Auto de Grayscale ou palette vers RGB
            if img.mode not in ("RGB" , "RGBA"):
                img = img.convert("RGB")

            img.thumbnail((400 , 300))

            self.img_preview = ImageTk.PhotoImage(img)
            self.preview_canvas.delete("all")
            self.preview_canvas.create_image(
                200 , 150 ,
                image=self.img_preview
            )

        except Exception as e:
            messagebox.showerror("Erreur preview" , str(e))

    # Password tools - Fonctions MDP - Generate - Show/Hide - Copy

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.entry_mdp.config(show="")
            self.entry_password.config(show="")
        else:
            self.entry_mdp.config(show="*")
            self.entry_password.config(show="*")

    def generate_password(self, length=16):
        characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        password = ''.join(random.choice(characters) for _ in range(length))
        self.entry_mdp.delete(0, tk.END)
        self.entry_mdp.insert(0, password)
        self.check_strength(password)

    def copy_password(self):
        password = self.entry_mdp.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copié", "Mot de passe copié (effacement auto dans 15s)")
            self.root.after(15000, self.clear_password_field)

    def clear_password_field(self):
        self.entry_mdp.delete(0, tk.END)

    def on_password_change(self, event=None):
        self.check_strength(self.entry_mdp.get())

    def check_strength(self, password):
        score = 0

        if len(password) >= 12: score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"\d", password): score += 1
        if re.search(r"[!@#$%^&*()-_=+]", password): score += 1

        if score <= 2:
            strength, color = "Faible", "red"
        elif score <= 4:
            strength, color = "Moyen", "orange"
        else:
            strength, color = "Fort", "green"

        self.strength_label.config(text=f"Robustesse du mot de passe : {strength}", fg=color)

    # Vault

    def add_entry(self):
        if not self.image_path:
            messagebox.showerror("Erreur", "Sélectionne une image du coffre")
            return

        name = self.entry_name.get().strip()
        url = self.entry_url.get().strip()
        login = self.entry_login.get().strip()
        mdp = self.entry_mdp.get().strip()
        password = self.entry_password.get().strip()

        if not (name and url and login and mdp and password):
            messagebox.showerror("Erreur", "Tous les champs sont obligatoires")
            return

        try:
            encrypted_bytes = decode_lsb(self.image_path)
            json_str = decrypt_data(encrypted_bytes, password)
            self.vault_data = json.loads(json_str)
        except:
            self.vault_data = {}

        self.vault_data[name] = {"url": url, "login": login, "mdp": mdp}

        json_str = json.dumps(self.vault_data)
        encrypted = encrypt_data(json_str, password)

        output_path = filedialog.asksaveasfilename(defaultextension=".png")
        if not output_path:
            return

        encode_lsb(self.image_path, output_path, encrypted)
        messagebox.showinfo("Succès", "Coffre mis à jour")
        self.show_preview(output_path)
        self.image_path = output_path

    def load_vault(self):
        password = self.entry_password.get().strip()
        if not password:
            messagebox.showerror("Erreur", "Mot de passe maître requis")
            return

        try:
            encrypted_bytes = decode_lsb(self.image_path)
            json_str = decrypt_data(encrypted_bytes, password)
            self.vault_data = json.loads(json_str)
            messagebox.showinfo("Succès", f"{len(self.vault_data)} entrées chargées")
        except:
            messagebox.showerror("Erreur", "Mot de passe incorrect ou image invalide")

    def list_entries(self):
        self.result_text.delete(1.0, tk.END)
        for name in self.vault_data:
            self.result_text.insert(tk.END, name + "\n")

    def decode_entry(self):
        selected = self.result_text.get(1.0, tk.END).strip().split("\n")[0]
        if selected in self.vault_data:
            entry = self.vault_data[selected]
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(
                tk.END,
                f"URL: {entry['url']}\nLogin: {entry['login']}\nMDP: {entry['mdp']}"
            )

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultGUI(root)
    root.mainloop()
