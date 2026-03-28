import secrets
import hashlib
import json
import os
from EllipticCurveDiffieHellman import curve, base_point, curve_order
from gost_gcm import gost_gcm_encrypt, gost_gcm_decrypt
from schnorr_signature import sign, verify

def generate_keypair():
    """Generates a private and public key pair."""
    private_key = secrets.randbelow(curve_order)
    while private_key == 0:
        private_key = secrets.randbelow(curve_order)
    public_key = curve.multiply_point_on_curve(private_key, base_point)
    return private_key, public_key

def derive_session_key(shared_secret_point):
    """Derives a 256-bit session key from the shared secret point's x-coordinate."""
    # Take the x-coordinate of the shared point
    x_coord = shared_secret_point[0]
    # Convert to bytes (32 bytes for 256-bit curve)
    x_bytes = x_coord.to_bytes(32, 'big')
    # Hash using SHA-256
    return hashlib.sha256(x_bytes).digest()

def serialize_payload(message, signature):
    """Serializes the message and signature into a byte string."""
    # Signature is (R, s), where R is a point (rx, ry)
    R, s = signature
    payload = {
        'message': message,
        'signature': {
            'R': R,
            's': s
        }
    }
    return json.dumps(payload).encode('utf-8')

def deserialize_payload(payload_bytes):
    """Deserializes the payload bytes back into message and signature."""
    payload = json.loads(payload_bytes.decode('utf-8'))
    message = payload['message']
    sig_dict = payload['signature']
    # R is a list [x, y] in json, convert to tuple
    R = tuple(sig_dict['R'])
    s = sig_dict['s']
    signature = (R, s)
    return message, signature

def main():
    print("=== Secure Communication Lifecycle: Setup & Handshake ===")
    
    # 1. Setup & Handshake
    print("\n[Step 1] Generating Keys...")
    alice_private, alice_public = generate_keypair()
    bob_private, bob_public = generate_keypair()
    
    print(f"Alice's Public Key: {alice_public}")
    print(f"Bob's Public Key:   {bob_public}")
    
    print("\n[Step 2] Computing Shared Secret...")
    # Alice computes S = dA * QB
    shared_secret_alice = curve.multiply_point_on_curve(alice_private, bob_public)
    # Bob computes S = dB * QA
    shared_secret_bob = curve.multiply_point_on_curve(bob_private, alice_public)
    
    assert shared_secret_alice == shared_secret_bob, "Shared secrets do not match!"
    print(f"Shared Secret Point: {shared_secret_alice}")
    
    # Derive Session Key
    session_key = derive_session_key(shared_secret_alice)
    print(f"Session Key (SHA-256 of S.x): {session_key.hex()}")
    
    print("\n=== Message Composition (Alice) ===")
    
    # 2. Message Composition
    message = "Confidential operations report: Project Alpha is go."
    print(f"Original Message: '{message}'")
    
    print("\n[Step 3] Signing Message (Schnorr)...")
    # Alice signs the message
    signature_alice = sign(alice_private, message)
    print(f"Signature (R, s): {signature_alice}")
    
    # Pack payload
    payload_plaintext = serialize_payload(message, signature_alice)
    
    print("\n=== Encryption (Alice) ===")
    
    # 3. Encryption
    print("\n[Step 4] Encrypting Payload with GOST-GCM...")
    iv = os.urandom(12) # 12 bytes IV
    ciphertext, tag = gost_gcm_encrypt(payload_plaintext, session_key, iv)
    
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")
    
    # Simulate transmission (Packet = IV + Ciphertext + Tag)
    print("\n--- Transmission ---")
    
    print("\n=== Decryption & Verification (Bob) ===")
    
    # 4. Decryption & Verification
    print("\n[Step 5] Bob Receives and Decrypts...")
    try:
        # Integrity Check happens here inside gost_gcm_decrypt
        decrypted_payload_bytes = gost_gcm_decrypt(ciphertext, session_key, iv, tag)
        print("GCM Decryption & Integrity Check: SUCCESS")
    except ValueError as e:
        print(f"GCM Decryption FAILED: {e}")
        return

    # Parse Payload
    received_message, received_signature = deserialize_payload(decrypted_payload_bytes)
    print(f"Decrypted Message: '{received_message}'")
    
    print("\n[Step 6] Verifying Signature...")
    # Bob verifies signature against Alice's public key
    is_authentic = verify(alice_public, received_message, received_signature)
    
    if is_authentic:
        print("Signature Verification: VALID. Origin confirmed as Alice.")
    else:
        print("Signature Verification: INVALID! Message may be forged.")

    # --- Tamper Test ---
    print("\n=== Tamper Detection Test ===")
    print("Modifying one byte of ciphertext...")
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF # Flip bits in first byte
    
    try:
        gost_gcm_decrypt(tampered_ciphertext, session_key, iv, tag)
        print("Tampered message accepted?! (FAILURE)")
    except ValueError as e:
        print(f"Tampered message rejected correctly: {e}")

if __name__ == "__main__":
    main()
