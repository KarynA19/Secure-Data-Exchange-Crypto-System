import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import os


from auth_keystore import (
    create_user_store,
    load_user_store,
    get_public_key,
    unlock_private_key,
)

# Import functionality from the existing modules
from main import generate_keypair, derive_session_key, serialize_payload, deserialize_payload
from EllipticCurveDiffieHellman import curve
from gost_gcm import gost_gcm_encrypt, gost_gcm_decrypt
from schnorr_signature import sign, verify

class GostMailApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GOST-GCM Secure Mail Exchange (Alice & Bob)")
        self.root.geometry("1100x700")

        self.store_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
        self.user_store = None

        self.alice_logged_in = False
        self.bob_logged_in = False
        
        # State variables
        self.alice_private = None
        self.alice_public = None
        self.bob_private = None
        self.bob_public = None
        self.session_key = None

        self.alice_session_key = None
        self.bob_session_key = None

        # UX/flow flags
        # Session keys should only be established after pressing the handshake button.
        self.session_established = False
        # Allow only one tamper action per sent packet.
        self.packet_tampered = False
        
        self.current_iv = None
        self.current_ciphertext = None
        self.current_tag = None
        
        self._setup_ui()

        # Load public keys if a store exists (private keys remain locked until login)
        self._try_load_user_store()
        self._update_ui_state()

    def _clear_session(self) -> None:
        self.session_established = False
        self.alice_session_key = None
        self.bob_session_key = None
        self.session_key = None
        
    def _setup_ui(self):
        # Step 0: Users / Login
        users_frame = ttk.LabelFrame(self.root, text="Step 0: Users & Login", padding=10)
        users_frame.pack(fill="x", padx=10, pady=5)

        self.btn_init_users = ttk.Button(users_frame, text="Initialize Users", command=self.initialize_users)
        self.btn_init_users.pack(side="left", padx=5)

        ttk.Separator(users_frame, orient="vertical").pack(side="left", fill="y", padx=8)

        self.btn_login_alice = ttk.Button(users_frame, text="Login Alice", command=self.login_alice)
        self.btn_login_alice.pack(side="left", padx=5)

        self.btn_logout_alice = ttk.Button(users_frame, text="Logout Alice", command=self.logout_alice, state="disabled")
        self.btn_logout_alice.pack(side="left", padx=5)

        self.lbl_alice_auth = ttk.Label(users_frame, text="Alice: locked", foreground="red")
        self.lbl_alice_auth.pack(side="left", padx=10)

        ttk.Separator(users_frame, orient="vertical").pack(side="left", fill="y", padx=8)

        self.btn_login_bob = ttk.Button(users_frame, text="Login Bob", command=self.login_bob)
        self.btn_login_bob.pack(side="left", padx=5)

        self.btn_logout_bob = ttk.Button(users_frame, text="Logout Bob", command=self.logout_bob, state="disabled")
        self.btn_logout_bob.pack(side="left", padx=5)

        self.lbl_bob_auth = ttk.Label(users_frame, text="Bob: locked", foreground="red")
        self.lbl_bob_auth.pack(side="left", padx=10)

        # Top Frame: Connection / Handshake
        setup_frame = ttk.LabelFrame(self.root, text="Step 1: Setup & Handshake", padding=10)
        setup_frame.pack(fill="x", padx=10, pady=5)
        
        self.btn_handshake = ttk.Button(setup_frame, text="Verify/Establish Session", command=self.perform_handshake)
        self.btn_handshake.pack(side="left", padx=5)
        
        self.lbl_status = ttk.Label(setup_frame, text="Status: Disconnected", foreground="red")
        self.lbl_status.pack(side="left", padx=10)
        
        self.lbl_session_info = ttk.Label(setup_frame, text="")
        self.lbl_session_info.pack(side="left", padx=10)

        # Main Content Area
        paned_window = ttk.PanedWindow(self.root, orient="horizontal")
        paned_window.pack(fill="both", expand=True, padx=10, pady=5)
        
        # --- ALICE (Left) ---
        alice_frame = ttk.LabelFrame(paned_window, text="Alice (Sender)", padding=10)
        paned_window.add(alice_frame, weight=1)
        
        ttk.Label(alice_frame, text="Message:").pack(anchor="w")
        self.txt_alice_msg = tk.Text(alice_frame, height=4, width=30)
        self.txt_alice_msg.pack(fill="x", pady=5)
        self.txt_alice_msg.insert("1.0", "Confidential operations report: Project Alpha is go.")
        
        self.btn_send = ttk.Button(alice_frame, text="Sign, Encrypt & Send", command=self.alice_send_message, state="disabled")
        self.btn_send.pack(pady=5)
        
        ttk.Label(alice_frame, text="Alice's Log:").pack(anchor="w", pady=(10, 0))
        self.log_alice = scrolledtext.ScrolledText(alice_frame, height=15, width=40, state="disabled")
        self.log_alice.pack(fill="both", expand=True)

        # --- TRANSIT (Center) ---
        transit_frame = ttk.Frame(paned_window, padding=10)
        paned_window.add(transit_frame, weight=0)
        
        ttk.Label(transit_frame, text="Channel").pack()
        ttk.Separator(transit_frame, orient="vertical").pack(fill="y", expand=True, padx=5)
        
        self.btn_tamper = ttk.Button(transit_frame, text="Tamper Packet\n(Flip Bit)", command=self.tamper_packet, state="disabled")
        self.btn_tamper.pack(pady=50)

        # --- BOB (Right) ---
        bob_frame = ttk.LabelFrame(paned_window, text="Bob (Receiver)", padding=10)
        paned_window.add(bob_frame, weight=1)
        
        self.btn_receive = ttk.Button(bob_frame, text="Receive & Decrypt", command=self.bob_receive_message, state="disabled")
        self.btn_receive.pack(pady=(28, 5)) 
        
        ttk.Label(bob_frame, text="Bob's Log:").pack(anchor="w", pady=(10, 0))
        self.log_bob = scrolledtext.ScrolledText(bob_frame, height=15, width=40, state="disabled")
        self.log_bob.pack(fill="both", expand=True)

    def log(self, widget, message):
        widget.config(state="normal")
        widget.insert(tk.END, message + "\n")
        widget.see(tk.END)
        widget.config(state="disabled")

    def _try_load_user_store(self):
        if not os.path.exists(self.store_path):
            self.user_store = None
            self.alice_public = None
            self.bob_public = None
            return

        try:
            self.user_store = load_user_store(self.store_path)
            self.alice_public = get_public_key(self.user_store, "alice")
            self.bob_public = get_public_key(self.user_store, "bob")
        except Exception as e:
            self.user_store = None
            self.alice_public = None
            self.bob_public = None
            messagebox.showerror("User Store Error", f"Failed to load users.json:\n{e}")

    def _prompt_password(self, title: str, user_label: str) -> str | None:
        return simpledialog.askstring(title, f"Enter password for {user_label}:", show="*")

    def _prompt_new_password_pair(self, user_label: str) -> str | None:
        # For this mock-up project, keep UX simple: one prompt, no confirmation.
        p1 = simpledialog.askstring("Set Password", f"Create password for {user_label}:", show="*")
        if not p1:
            return None
        return p1

    def _update_ui_state(self):
        has_store = self.user_store is not None

        # Auth labels
        self.lbl_alice_auth.config(
            text=("Alice: unlocked" if self.alice_logged_in else "Alice: locked"),
            foreground=("green" if self.alice_logged_in else "red"),
        )
        self.lbl_bob_auth.config(
            text=("Bob: unlocked" if self.bob_logged_in else "Bob: locked"),
            foreground=("green" if self.bob_logged_in else "red"),
        )

        # Login buttons
        self.btn_login_alice.config(state=("normal" if (has_store and not self.alice_logged_in) else "disabled"))
        self.btn_logout_alice.config(state=("normal" if self.alice_logged_in else "disabled"))
        self.btn_login_bob.config(state=("normal" if (has_store and not self.bob_logged_in) else "disabled"))
        self.btn_logout_bob.config(state=("normal" if self.bob_logged_in else "disabled"))

        # Session status
        if not has_store:
            self.lbl_status.config(text="Status: No users.json (Initialize Users)", foreground="red")
            self.lbl_session_info.config(text="")
        elif self.session_established and self.alice_session_key and self.bob_session_key and self.alice_session_key == self.bob_session_key:
            self.lbl_status.config(text="Status: Connected (Secure Session)", foreground="green")
            self.lbl_session_info.config(text=f"Session Key: {self.alice_session_key.hex()[:10]}...")
        elif self.alice_logged_in or self.bob_logged_in:
            if self.alice_logged_in and self.bob_logged_in:
                self.lbl_status.config(text="Status: Ready (Press Verify/Establish Session)", foreground="orange")
            else:
                self.lbl_status.config(text="Status: Partial (Waiting for other user)", foreground="orange")
            self.lbl_session_info.config(text="")
        else:
            self.lbl_status.config(text="Status: Disconnected", foreground="red")
            self.lbl_session_info.config(text="")

        # Action buttons
        can_send = has_store and self.alice_logged_in and self.session_established and (self.alice_session_key is not None)
        self.btn_send.config(state=("normal" if can_send else "disabled"))

        can_receive = (
            has_store
            and self.bob_logged_in
            and self.session_established
            and (self.bob_session_key is not None)
            and (self.current_ciphertext is not None)
        )
        self.btn_receive.config(state=("normal" if can_receive else "disabled"))

        can_tamper = (
            self.current_ciphertext is not None
            and self.current_tag is not None
            and not self.packet_tampered
        )
        self.btn_tamper.config(state=("normal" if can_tamper else "disabled"))

        # Handshake button is only meaningful when both are logged in.
        can_handshake = has_store and self.alice_logged_in and self.bob_logged_in
        self.btn_handshake.config(state=("normal" if can_handshake else "disabled"))

    def _recompute_session_keys(self):
        # Session keys should not be derived automatically; they are established in perform_handshake.
        # Keep this method for callers, but make it a no-op unless a session is already established.
        if not self.session_established:
            self.alice_session_key = None
            self.bob_session_key = None
            self.session_key = None
            return
        
    def perform_handshake(self):
        self.log_alice.config(state="normal"); self.log_alice.delete(1.0, tk.END); self.log_alice.config(state="disabled")
        self.log_bob.config(state="normal"); self.log_bob.delete(1.0, tk.END); self.log_bob.config(state="disabled")

        if self.user_store is None:
            messagebox.showwarning("Not Ready", "Initialize Users first (creates users.json).")
            return
        if not (self.alice_logged_in and self.bob_logged_in):
            messagebox.showwarning("Not Ready", "Login both Alice and Bob to verify the shared key on both sides.")
            return

        # New handshake invalidates any previous session state.
        self._clear_session()

        # Compute shared secrets from both perspectives and verify match
        shared_secret_alice = curve.multiply_point_on_curve(self.alice_private, self.bob_public)
        shared_secret_bob = curve.multiply_point_on_curve(self.bob_private, self.alice_public)

        if shared_secret_alice != shared_secret_bob:
            messagebox.showerror("Handshake Failed", "ECDH shared secrets did not match.")
            return

        self.alice_session_key = derive_session_key(shared_secret_alice)
        self.bob_session_key = derive_session_key(shared_secret_bob)
        self.session_key = self.alice_session_key
        self.session_established = True

        self.log(self.log_alice, "ECDH shared secret computed (Alice side).")
        self.log(self.log_bob, "ECDH shared secret computed (Bob side).")
        self.log(self.log_alice, f"Session key preview: {self.session_key.hex()[:10]}...")
        self.log(self.log_bob, f"Session key preview: {self.session_key.hex()[:10]}...")

        self._update_ui_state()

    def initialize_users(self):
        if os.path.exists(self.store_path):
            overwrite = messagebox.askyesno(
                "Overwrite users.json?",
                "A users.json already exists. Overwrite it? (This will reset keys/passwords)",
            )
            if not overwrite:
                return
        else:
            overwrite = False

        alice_pw = self._prompt_new_password_pair("Alice")
        if alice_pw is None:
            return
        bob_pw = self._prompt_new_password_pair("Bob")
        if bob_pw is None:
            return

        try:
            self.user_store = create_user_store(self.store_path, alice_password=alice_pw, bob_password=bob_pw, overwrite=overwrite)
            self.alice_public = get_public_key(self.user_store, "alice")
            self.bob_public = get_public_key(self.user_store, "bob")
        except Exception as e:
            messagebox.showerror("Initialization Failed", f"Failed to create users.json:\n{e}")
            return

        # Reset runtime state
        self._clear_session()
        self.logout_alice(silent=True)
        self.logout_bob(silent=True)
        self.current_iv = None
        self.current_ciphertext = None
        self.current_tag = None
        self.packet_tampered = False

        self.log(self.log_alice, "User store initialized (public keys saved; private keys encrypted).")
        self.log(self.log_bob, "User store initialized (public keys saved; private keys encrypted).")
        messagebox.showinfo("Initialized", "Users initialized. Now login as Alice and/or Bob.")
        self._update_ui_state()

    def login_alice(self):
        if self.user_store is None:
            messagebox.showwarning("Not Ready", "Initialize Users first.")
            return
        password = self._prompt_password("Login", "Alice")
        if password is None:
            return
        try:
            self.alice_private = unlock_private_key(self.user_store, "alice", password)
            self.alice_logged_in = True
        except Exception:
            messagebox.showerror("Login Failed", "Invalid password (or corrupted store).")
            return

        # Logging in changes handshake state; require explicit handshake button.
        self._clear_session()
        self.log(self.log_alice, "Alice logged in: private key unlocked.")
        self._update_ui_state()

    def login_bob(self):
        if self.user_store is None:
            messagebox.showwarning("Not Ready", "Initialize Users first.")
            return
        password = self._prompt_password("Login", "Bob")
        if password is None:
            return
        try:
            self.bob_private = unlock_private_key(self.user_store, "bob", password)
            self.bob_logged_in = True
        except Exception:
            messagebox.showerror("Login Failed", "Invalid password (or corrupted store).")
            return

        # Logging in changes handshake state; require explicit handshake button.
        self._clear_session()
        self.log(self.log_bob, "Bob logged in: private key unlocked.")
        self._update_ui_state()

    def logout_alice(self, silent: bool = False):
        self.alice_private = None
        self.alice_logged_in = False
        self._clear_session()
        if not silent:
            self.log(self.log_alice, "Alice logged out: private key cleared from memory.")
        self._update_ui_state()

    def logout_bob(self, silent: bool = False):
        self.bob_private = None
        self.bob_logged_in = False
        self._clear_session()
        if not silent:
            self.log(self.log_bob, "Bob logged out: private key cleared from memory.")
        self._update_ui_state()

    def alice_send_message(self):
        if not self.alice_logged_in or self.alice_private is None:
            messagebox.showwarning("Not Ready", "Login as Alice first.")
            return
        if self.alice_session_key is None:
            messagebox.showwarning("Not Ready", "Session key not available. Ensure users.json exists and Bob's public key is loaded.")
            return

        message = self.txt_alice_msg.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Input Error", "Please enter a message.")
            return

        self.log(self.log_alice, f"\n--- Sending Message ---")
        self.log(self.log_alice, f"Plaintext: {message}")
        
        # 1. Sign
        signature = sign(self.alice_private, message)
        self.log(self.log_alice, "Schnorr Signature generated.")
        
        # 2. Serialize
        payload = serialize_payload(message, signature)
        
        # 3. Encrypt
        iv = os.urandom(12)
        ciphertext, tag = gost_gcm_encrypt(payload, self.alice_session_key, iv)
        
        self.current_iv = iv
        self.current_ciphertext = bytearray(ciphertext) # Mutable for tampering
        self.current_tag = tag
        self.packet_tampered = False
        
        self.log(self.log_alice, "Encrypted with GOST-GCM.")
        self.log(self.log_alice, f"IV: {iv.hex()}")
        self.log(self.log_alice, f"Tag: {tag.hex()}")
        self.log(self.log_alice, "Packet sent to channel.")
        
        self.btn_receive.config(state="normal")
        self.btn_tamper.config(state="normal")
        self.btn_send.config(state="disabled") # Wait for Bob to read before sending another (simple flow)

        self._update_ui_state()

    def bob_receive_message(self):
        if not self.bob_logged_in or self.bob_private is None:
            messagebox.showwarning("Not Ready", "Login as Bob first.")
            return
        if self.bob_session_key is None:
            messagebox.showwarning("Not Ready", "Session key not available. Ensure users.json exists and Alice's public key is loaded.")
            return
        if self.current_ciphertext is None:
            messagebox.showwarning("Not Ready", "No packet to receive yet.")
            return

        self.log(self.log_bob, f"\n--- Receiving Packet ---")
        self.log(self.log_bob, f"IV: {self.current_iv.hex()}")
        self.log(self.log_bob, f"Tag: {self.current_tag.hex()}")
        
        try:
            # 1. Decrypt (Integrity Check)
            decrypted_payload = gost_gcm_decrypt(
                self.current_ciphertext, 
                self.bob_session_key, 
                self.current_iv, 
                self.current_tag
            )
            self.log(self.log_bob, "GCM Decryption & Integrity Check: SUCCESS")
            
            # 2. Deserialize
            message, signature = deserialize_payload(decrypted_payload)
            self.log(self.log_bob, f"Decrypted Message: {message}")
            
            # 3. Verify Signature
            is_valid = verify(self.alice_public, message, signature)
            if is_valid:
                self.log(self.log_bob, "Signature Verification: VALID (From Alice)")
                messagebox.showinfo("Success", "Message received and verified securely!")
            else:
                self.log(self.log_bob, "Signature Verification: INVALID!")
                messagebox.showerror("Security Alert", "Signature verification failed! Sender ID unconfirmed.")
                
        except ValueError as e:
            self.log(self.log_bob, f"GCM Decryption FAILED: {e}")
            messagebox.showerror("Security Alert", f"Tampering Detected!\nGCM Integrity Check Failed: {e}")
            
        self.btn_send.config(state="normal")
        self.btn_receive.config(state="disabled")
        self.btn_tamper.config(state="disabled")

        self._update_ui_state()

    def tamper_packet(self):
        if self.current_ciphertext:
            # Flip last bit of the first byte
            self.current_ciphertext[0] ^= 0x01
            self.log(self.log_alice, ">>> ATTACKER: Ciphertext modified in transit! <<<")
            self.log(self.log_bob, ">>> ATTACKER: Packet modified in transit! <<<")
            self.packet_tampered = True
            self.btn_tamper.config(state="disabled") # Can only tamper once per send

        self._update_ui_state()

if __name__ == "__main__":
    root = tk.Tk()
    app = GostMailApp(root)
    root.mainloop()
