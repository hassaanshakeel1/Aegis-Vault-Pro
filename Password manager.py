# ==========================================
# 1. SYSTEM INITIALIZATION & AUTO-INSTALL
# ==========================================
import subprocess
import sys
import os
import shutil
import time
import threading
import json
import base64
import zlib
import secrets
import string
from tkinter import messagebox

# --- Dependency Enforcer ---
REQUIRED = ["customtkinter", "cryptography", "packaging"]


def install_deps():
    missing = []
    for pkg in REQUIRED:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"⚡ [Aegis Vault Pro] Installing core modules: {', '.join(missing)}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
            print("✅ Modules loaded. Booting sequence initiated...")
            time.sleep(1)
        except Exception as e:
            print(f"❌ Critical Error: {e}")
            sys.exit(1)


install_deps()

# ==========================================
# 2. IMPORTS & PRO THEME CONFIGURATION
# ==========================================
import customtkinter as ctk
import tkinter as tk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# --- PRO THEME: NEON ABYSS ---
THEME = {
    "bg": "#0B0E14",  # Deepest Blue-Black
    "surface": "#151A22",  # Elevated Dark Surface
    "surface_hover": "#1E2530",  # Lighter Surface for hover
    "accent": "#00E5FF",  # Electric Cyan
    "accent_hover": "#00B2CC",  # Deep Cyan
    "text_main": "#F8FAFC",  # Crisp White
    "text_muted": "#94A3B8",  # Slate Gray
    "success": "#10B981",  # Emerald Green
    "danger": "#EF4444",  # Rose Red
    "warning": "#F59E0B"  # Amber
}

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


# ==========================================
# 3. BACKEND: QUANTUM CORE ENCRYPTION
# ==========================================
class QuantumCore:
    def __init__(self, filepath="aegis_secure.vault"):
        self.filepath = filepath
        self.key = None
        self.salt = None
        self.data = []

    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        if not salt: salt = os.urandom(16)
        self.salt = salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # Optimized for fast UI + High Security
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def unlock(self, password: str) -> bool:
        if not os.path.exists(self.filepath): return False
        try:
            with open(self.filepath, 'rb') as f:
                raw = f.read()
            file_salt, encrypted_payload = raw[:16], raw[16:]
            key = self.derive_key(password, file_salt)
            fernet = Fernet(key)
            self.data = json.loads(zlib.decompress(fernet.decrypt(encrypted_payload)).decode())
            self.key = key
            return True
        except Exception:
            return False

    def create(self, password: str):
        self.key = self.derive_key(password)
        self.data = []
        self.save()

    def save(self):
        if not self.key: return
        encrypted = Fernet(self.key).encrypt(zlib.compress(json.dumps(self.data).encode()))
        with open(self.filepath + ".tmp", 'wb') as f: f.write(self.salt + encrypted)
        shutil.move(self.filepath + ".tmp", self.filepath)

    def lock(self):
        self.key = None
        self.data = []


# ==========================================
# 4. GUI COMPONENTS: ANIMATED TOAST
# ==========================================
class AnimatedToast(ctk.CTkFrame):
    """A sleek sliding notification."""

    def __init__(self, master, message, icon="ℹ️", color=THEME["accent"]):
        super().__init__(master, fg_color=THEME["surface"], corner_radius=8, border_width=1, border_color=color)

        self.start_y = 1.05  # Start off-screen
        self.target_y = 0.92  # Target position
        self.current_y = self.start_y
        self.place(relx=0.98, rely=self.current_y, anchor="se")

        ctk.CTkLabel(self, text=icon, font=("Segoe UI", 22)).pack(side="left", padx=(15, 10), pady=12)
        ctk.CTkLabel(self, text=message, font=("Segoe UI", 14, "bold"), text_color=THEME["text_main"]).pack(side="left",
                                                                                                            padx=(0,
                                                                                                                  20))

        self.animate_in()
        self.after(3500, self.animate_out)

    def animate_in(self):
        if self.current_y > self.target_y:
            self.current_y -= 0.01
            self.place(relx=0.98, rely=self.current_y, anchor="se")
            self.after(10, self.animate_in)

    def animate_out(self):
        if self.current_y < self.start_y:
            self.current_y += 0.01
            self.place(relx=0.98, rely=self.current_y, anchor="se")
            self.after(10, self.animate_out)
        else:
            self.destroy()


# ==========================================
# 5. MAIN APPLICATION
# ==========================================
class AegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Aegis Vault Pro | Hassaan Shakeel")
        self.geometry("1100x750")
        self.minsize(950, 650)
        self.configure(fg_color=THEME["bg"])

        self.core = QuantumCore()
        self.current_view = None
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.render_vault_list)

        self.show_splash_screen()

    # --- SCREEN: ANIMATED SPLASH ---
    def show_splash_screen(self):
        self.splash = ctk.CTkFrame(self, fg_color=THEME["bg"])
        self.splash.place(relx=0, rely=0, relwidth=1, relheight=1)

        center = ctk.CTkFrame(self.splash, fg_color="transparent")
        center.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center, text="🛡️", font=("Segoe UI", 70)).pack(pady=(0, 10))
        # Fixed: Removed letter_spacing argument
        ctk.CTkLabel(center, text="A E G I S   V A U L T   P R O", font=("Segoe UI", 32, "bold"),
                     text_color=THEME["accent"]).pack()
        ctk.CTkLabel(center, text="Lead Architect: Hassaan Shakeel", font=("Segoe UI", 14, "italic"),
                     text_color=THEME["text_muted"]).pack(pady=(5, 30))

        self.progress = ctk.CTkProgressBar(center, width=350, height=4, progress_color=THEME["accent"],
                                           fg_color=THEME["surface"])
        self.progress.pack()
        self.progress.set(0)

        def load_anim():
            for i in range(101):
                time.sleep(0.01)
                self.progress.set(i / 100)
            self.splash.destroy()
            self.show_login()

        threading.Thread(target=load_anim, daemon=True).start()

    # --- SCREEN: LOGIN ---
    def show_login(self):
        self.clear_ui()

        panel = ctk.CTkFrame(self, width=420, height=520, corner_radius=15, fg_color=THEME["surface"])
        panel.place(relx=0.5, rely=0.5, anchor="center")
        panel.pack_propagate(False)

        ctk.CTkLabel(panel, text="🔐", font=("Segoe UI", 55)).pack(pady=(45, 10))
        ctk.CTkLabel(panel, text="Identity Verification", font=("Segoe UI", 24, "bold"),
                     text_color=THEME["text_main"]).pack()
        ctk.CTkLabel(panel, text="Hassaan Shakeel Systems", font=("Segoe UI", 12), text_color=THEME["text_muted"]).pack(
            pady=(0, 30))

        exists = os.path.exists(self.core.filepath)
        msg = "Enter Master Key" if exists else "Create Master Key"

        self.pwd_entry = ctk.CTkEntry(panel, width=320, height=50, show="●", placeholder_text=msg,
                                      font=("Segoe UI", 16), justify="center", border_color=THEME["surface_hover"])
        self.pwd_entry.pack(pady=15)
        self.pwd_entry.bind("<Return>", lambda e: self.attempt_login(exists))

        btn_txt = "ACCESS VAULT" if exists else "INITIALIZE VAULT"
        ctk.CTkButton(panel, text=btn_txt, width=320, height=50, fg_color=THEME["accent"], text_color="#000",
                      hover_color=THEME["accent_hover"], font=("Segoe UI", 15, "bold"),
                      command=lambda: self.attempt_login(exists)).pack(pady=10)

    def attempt_login(self, exists):
        pwd = self.pwd_entry.get()
        if not pwd: return

        if exists:
            if self.core.unlock(pwd):
                self.show_main_interface()
                AnimatedToast(self, "Decryption Successful", "🔓", THEME["success"])
            else:
                self.pwd_entry.configure(border_color=THEME["danger"])
                AnimatedToast(self, "Access Denied. Invalid Key.", "❌", THEME["danger"])
        else:
            self.core.create(pwd)
            self.show_main_interface()
            AnimatedToast(self, "Secure Vault Initialized", "✅", THEME["success"])

    # --- SCREEN: MAIN INTERFACE ---
    def show_main_interface(self):
        self.clear_ui()

        sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color=THEME["surface"])
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="🛡️ AEGIS", font=("Segoe UI", 26, "bold"), text_color=THEME["accent"]).pack(
            pady=(40, 0))
        # Fixed: Removed letter_spacing argument
        ctk.CTkLabel(sidebar, text="P R O   E D I T I O N", font=("Segoe UI", 10, "bold"),
                     text_color=THEME["text_muted"]).pack(pady=(0, 30))

        self.create_nav_btn(sidebar, "📊 Dashboard Overview", lambda: self.switch_view("DASHBOARD"))
        self.create_nav_btn(sidebar, "🔑 Credential Vault", lambda: self.switch_view("VAULT"))
        self.create_nav_btn(sidebar, "🎲 Entropy Generator", lambda: self.switch_view("GEN"))

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", pady=20)

        ctk.CTkLabel(footer, text="Lead Developer:", font=("Segoe UI", 11), text_color=THEME["text_muted"]).pack()
        ctk.CTkLabel(footer, text="Hassaan Shakeel", font=("Segoe UI", 14, "bold"),
                     text_color=THEME["text_main"]).pack()

        ctk.CTkButton(footer, text="🔒 Lock Vault", fg_color="transparent", border_width=1.5,
                      border_color=THEME["danger"], text_color=THEME["danger"], hover_color="#3A1515",
                      font=("Segoe UI", 13, "bold"), command=self.lock_app).pack(pady=(20, 0), padx=30, fill="x")

        self.content_area = ctk.CTkFrame(self, fg_color="transparent")
        self.content_area.pack(side="right", fill="both", expand=True, padx=30, pady=30)

        self.switch_view("DASHBOARD")

    def create_nav_btn(self, parent, text, cmd):
        ctk.CTkButton(parent, text=text, anchor="w", fg_color="transparent", height=45, font=("Segoe UI", 15),
                      text_color=THEME["text_main"], hover_color=THEME["surface_hover"], command=cmd).pack(fill="x",
                                                                                                           padx=15,
                                                                                                           pady=4)

    def switch_view(self, view_name):
        self.current_view = view_name
        for w in self.content_area.winfo_children(): w.destroy()

        if view_name == "DASHBOARD":
            self.render_dashboard()
        elif view_name == "VAULT":
            self.render_vault()
        elif view_name == "GEN":
            self.render_generator()

    # --- VIEW: DASHBOARD WITH ANIMATED COUNTERS ---
    def render_dashboard(self):
        ctk.CTkLabel(self.content_area, text="Security Dashboard", font=("Segoe UI", 32, "bold"),
                     text_color=THEME["text_main"]).pack(anchor="w", pady=(0, 30))

        grid = ctk.CTkFrame(self.content_area, fg_color="transparent")
        grid.pack(fill="x")

        total_items = len(self.core.data)
        weak_items = sum(1 for x in self.core.data if len(x['password']) < 12)

        self.create_stat_card(grid, "Total Credentials", total_items, "📦", THEME["accent"])
        self.create_stat_card(grid, "Weak Passwords", weak_items, "⚠️",
                              THEME["danger"] if weak_items > 0 else THEME["success"])
        self.create_stat_card(grid, "Protocol", "AES-256", "🛡️", THEME["success"], is_text=True)

        ctk.CTkLabel(self.content_area, text="Vault Health Score", font=("Segoe UI", 20, "bold")).pack(anchor="w",
                                                                                                       pady=(40, 15))

        score = 100 - (weak_items * 10) if total_items > 0 else 100
        score = max(0, score)
        bar_color = THEME["success"] if score > 80 else THEME["warning"] if score > 50 else THEME["danger"]

        bar = ctk.CTkProgressBar(self.content_area, height=12, progress_color=bar_color, fg_color=THEME["surface"])
        bar.pack(fill="x")
        bar.set(0)

        def fill_bar():
            for i in range(score + 1):
                time.sleep(0.005)
                bar.set(i / 100)

        threading.Thread(target=fill_bar, daemon=True).start()

        ctk.CTkLabel(self.content_area, text=f"{score}% Optimized", font=("Segoe UI", 14, "bold"),
                     text_color=bar_color).pack(anchor="e", pady=5)

    def create_stat_card(self, parent, title, target_val, icon, color, is_text=False):
        card = ctk.CTkFrame(parent, fg_color=THEME["surface"], corner_radius=12, height=140)
        card.pack(side="left", fill="both", expand=True, padx=8)
        card.pack_propagate(False)

        ctk.CTkLabel(card, text=icon, font=("Segoe UI", 32)).pack(pady=(20, 5))

        val_label = ctk.CTkLabel(card, text="0" if not is_text else target_val, font=("Segoe UI", 28, "bold"),
                                 text_color=color)
        val_label.pack()

        ctk.CTkLabel(card, text=title, font=("Segoe UI", 13), text_color=THEME["text_muted"]).pack(pady=(0, 20))

        if not is_text and target_val > 0:
            def count_up(current):
                if current <= target_val:
                    val_label.configure(text=str(current))
                    self.after(20, lambda: count_up(current + 1))

            self.after(100, lambda: count_up(1))

    # --- VIEW: VAULT LIST ---
    def render_vault(self):
        top = ctk.CTkFrame(self.content_area, fg_color="transparent")
        top.pack(fill="x", pady=(0, 20))

        ctk.CTkEntry(top, textvariable=self.search_var, width=350, height=45, placeholder_text="🔍 Search Vault...",
                     font=("Segoe UI", 15), border_color=THEME["surface"]).pack(side="left")
        ctk.CTkButton(top, text="➕ Add Credential", width=150, height=45, fg_color=THEME["accent"], text_color="#000",
                      hover_color=THEME["accent_hover"], font=("Segoe UI", 14, "bold"), command=self.open_editor).pack(
            side="right")

        self.vault_scroll = ctk.CTkScrollableFrame(self.content_area, fg_color="transparent")
        self.vault_scroll.pack(fill="both", expand=True)
        self.render_vault_list()

    def render_vault_list(self, *args):
        for w in self.vault_scroll.winfo_children(): w.destroy()

        query = self.search_var.get().lower()

        for idx, entry in enumerate(self.core.data):
            if query not in entry['service'].lower() and query not in entry['username'].lower():
                continue

            row = ctk.CTkFrame(self.vault_scroll, fg_color=THEME["surface"], height=75, corner_radius=10)
            row.pack(fill="x", pady=6, padx=5)
            row.pack_propagate(False)

            ctk.CTkLabel(row, text="🌐", font=("Segoe UI", 24)).pack(side="left", padx=20)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="y", pady=12)
            ctk.CTkLabel(info, text=entry['service'], font=("Segoe UI", 17, "bold"),
                         text_color=THEME["text_main"]).pack(anchor="w")
            ctk.CTkLabel(info, text=entry['username'], font=("Segoe UI", 13), text_color=THEME["text_muted"]).pack(
                anchor="w")

            cmds = ctk.CTkFrame(row, fg_color="transparent")
            cmds.pack(side="right", padx=15, pady=15)

            ctk.CTkButton(cmds, text="📋 Copy", width=70, height=35, fg_color="#1D4ED8", hover_color="#2563EB",
                          font=("Segoe UI", 13, "bold"), command=lambda p=entry['password']: self.copy_pass(p)).pack(
                side="left", padx=4)
            ctk.CTkButton(cmds, text="✏️ Edit", width=70, height=35, fg_color="#4F46E5", hover_color="#6366F1",
                          font=("Segoe UI", 13, "bold"), command=lambda i=idx: self.open_editor(i)).pack(side="left",
                                                                                                         padx=4)
            ctk.CTkButton(cmds, text="🗑️", width=40, height=35, fg_color=THEME["danger"], hover_color="#B91C1C",
                          command=lambda i=idx: self.delete_entry(i)).pack(side="left", padx=4)

    def open_editor(self, index=None):
        win = ctk.CTkToplevel(self)
        win.title("Vault Editor")
        win.geometry("500x580")
        win.attributes("-topmost", True)
        win.configure(fg_color=THEME["bg"])

        is_edit = index is not None
        data = self.core.data[index] if is_edit else {"service": "", "username": "", "password": ""}

        ctk.CTkLabel(win, text="Credential Details", font=("Segoe UI", 24, "bold"), text_color=THEME["text_main"]).pack(
            pady=(30, 20))

        def entry_field(lbl, val, is_pwd=False):
            ctk.CTkLabel(win, text=lbl, font=("Segoe UI", 14), text_color=THEME["text_muted"]).pack(anchor="w", padx=50)
            e = ctk.CTkEntry(win, width=400, height=45, font=("Segoe UI", 15), show="*" if is_pwd else "")
            e.insert(0, val)
            e.pack(pady=(5, 15))
            return e

        e_svc = entry_field("Website / Service Name", data['service'])
        e_usr = entry_field("Username / Email", data['username'])
        e_pwd = entry_field("Password", data['password'], is_pwd=True)

        def gen():
            p = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(20))
            e_pwd.delete(0, 'end')
            e_pwd.insert(0, p)
            e_pwd.configure(show="")

        ctk.CTkButton(win, text="🎲 Generate Strong Password", fg_color="transparent", border_width=1,
                      border_color=THEME["accent"], text_color=THEME["accent"], hover_color="#0A2A33", height=40,
                      font=("Segoe UI", 14), command=gen).pack(pady=5)

        def save():
            new_data = {"service": e_svc.get(), "username": e_usr.get(), "password": e_pwd.get()}
            if not new_data['service'] or not new_data['password']: return

            if is_edit:
                self.core.data[index] = new_data
            else:
                self.core.data.append(new_data)

            self.core.save()
            self.render_vault_list()
            win.destroy()
            AnimatedToast(self, "Credential Saved", "💾", THEME["success"])

        ctk.CTkButton(win, text="SAVE TO VAULT", width=400, height=50, fg_color=THEME["accent"], text_color="#000",
                      hover_color=THEME["accent_hover"], font=("Segoe UI", 16, "bold"), command=save).pack(
            pady=(30, 10))

    # --- VIEW: GENERATOR ---
    def render_generator(self):
        frame = ctk.CTkFrame(self.content_area, fg_color=THEME["surface"], corner_radius=15)
        frame.pack(expand=True, fill="both", padx=60, pady=60)

        ctk.CTkLabel(frame, text="Entropy Generator", font=("Segoe UI", 32, "bold"),
                     text_color=THEME["text_main"]).pack(pady=(60, 20))
        ctk.CTkLabel(frame, text="Generate cryptographically secure passwords locally.", font=("Segoe UI", 14),
                     text_color=THEME["text_muted"]).pack()

        self.gen_output = ctk.CTkEntry(frame, width=550, height=70, font=("Consolas", 26), justify="center",
                                       fg_color=THEME["bg"], border_width=0)
        self.gen_output.pack(pady=40)

        def generate():
            chars = string.ascii_letters + string.digits + "!@#$%^&*()_+"
            pwd = "".join(secrets.choice(chars) for _ in range(24))
            self.gen_output.delete(0, 'end')
            self.gen_output.insert(0, pwd)

        ctk.CTkButton(frame, text="⚡ GENERATE", width=350, height=55, fg_color=THEME["accent"], text_color="#000",
                      hover_color=THEME["accent_hover"], font=("Segoe UI", 18, "bold"), command=generate).pack(pady=10)
        ctk.CTkButton(frame, text="📋 COPY TO CLIPBOARD", width=350, height=45, fg_color="transparent", border_width=1.5,
                      border_color=THEME["text_muted"], text_color=THEME["text_main"], font=("Segoe UI", 14, "bold"),
                      command=lambda: self.copy_pass(self.gen_output.get())).pack(pady=10)

    # --- UTILITIES ---
    def copy_pass(self, pwd):
        self.clipboard_clear()
        self.clipboard_append(pwd)
        AnimatedToast(self, "Password Copied (Clears in 30s)", "📋", THEME["accent"])
        threading.Thread(target=self.clipboard_timer, daemon=True).start()

    def clipboard_timer(self):
        time.sleep(30)
        self.clipboard_clear()

    def delete_entry(self, index):
        if messagebox.askyesno("Confirm Delete", "Permanently delete this credential?"):
            del self.core.data[index]
            self.core.save()
            self.render_vault_list()
            AnimatedToast(self, "Entry Deleted", "🗑️", THEME["danger"])

    def lock_app(self):
        self.core.lock()
        self.show_login()
        AnimatedToast(self, "Vault Secured", "🔒", THEME["success"])

    def clear_ui(self):
        for widget in self.winfo_children(): widget.destroy()


if __name__ == "__main__":
    app = AegisApp()
    app.mainloop()