import base64
import hashlib
import json
import os
from typing import Any, Dict, Tuple

from gost_gcm import gost_gcm_encrypt, gost_gcm_decrypt
from main import generate_keypair


PBKDF2_DEFAULT_ITERATIONS = 200_000
PBKDF2_SALT_LEN = 16
PRIVKEY_LEN_BYTES = 32  # secp256k1-sized scalars
GCM_IV_LEN = 12


def _consttime_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison (replacement for hmac.compare_digest)."""
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _hmac_digest(hash_name: str, key: bytes, msg: bytes) -> bytes:
    """Manual HMAC(hash_name, key, msg). Avoids using the stdlib 'hmac' module."""
    if not isinstance(key, (bytes, bytearray)) or not isinstance(msg, (bytes, bytearray)):
        raise TypeError("key and msg must be bytes")

    h = hashlib.new(hash_name)
    block_size = h.block_size

    # If key is longer than blocksize, shorten it by hashing.
    if len(key) > block_size:
        key = hashlib.new(hash_name, bytes(key)).digest()

    # Pad key to blocksize.
    if len(key) < block_size:
        key = bytes(key) + b"\x00" * (block_size - len(key))
    else:
        key = bytes(key)

    o_key_pad = bytes((b ^ 0x5C) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)

    inner = hashlib.new(hash_name, i_key_pad + bytes(msg)).digest()
    return hashlib.new(hash_name, o_key_pad + inner).digest()


def _pbkdf2_hmac(hash_name: str, password: bytes, salt: bytes, *, iterations: int, dklen: int) -> bytes:
    """PBKDF2 with HMAC(hash_name) PRF, implemented directly from the spec."""
    if iterations <= 0:
        raise ValueError("iterations must be >= 1")
    if dklen <= 0:
        raise ValueError("dklen must be >= 1")

    hlen = hashlib.new(hash_name).digest_size
    blocks_needed = (dklen + hlen - 1) // hlen

    out = bytearray()
    for block_index in range(1, blocks_needed + 1):
        u = _hmac_digest(hash_name, password, bytes(salt) + block_index.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(2, iterations + 1):
            u = _hmac_digest(hash_name, password, u)
            for j in range(hlen):
                t[j] ^= u[j]
        out.extend(t)

    return bytes(out[:dklen])


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def pbkdf2_sha256(password: str, salt: bytes, *, iterations: int, dklen: int = 32) -> bytes:
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("Salt must be bytes (>= 8 bytes)")
    if iterations < 50_000:
        raise ValueError("PBKDF2 iterations too low")
    return _pbkdf2_hmac("sha256", password.encode("utf-8"), bytes(salt), iterations=iterations, dklen=dklen)


def make_password_record(password: str, *, iterations: int = PBKDF2_DEFAULT_ITERATIONS) -> Dict[str, Any]:
    salt = os.urandom(PBKDF2_SALT_LEN)
    dk = pbkdf2_sha256(password, salt, iterations=iterations, dklen=32)
    return {
        "kdf": "pbkdf2_hmac_sha256",
        "iterations": iterations,
        "salt": _b64e(salt),
        "dk": _b64e(dk),
    }


def verify_password(record: Dict[str, Any], password: str) -> bool:
    try:
        if record.get("kdf") != "pbkdf2_hmac_sha256":
            return False
        iterations = int(record["iterations"])
        salt = _b64d(record["salt"])
        expected = _b64d(record["dk"])
        actual = pbkdf2_sha256(password, salt, iterations=iterations, dklen=len(expected))
        return _consttime_compare(actual, expected)
    except Exception:
        return False


def encrypt_private_key(private_key: int, password: str, *, iterations: int = PBKDF2_DEFAULT_ITERATIONS) -> Dict[str, Any]:
    if not isinstance(private_key, int) or private_key <= 0:
        raise ValueError("Private key must be a positive integer")

    salt = os.urandom(PBKDF2_SALT_LEN)
    key = pbkdf2_sha256(password, salt, iterations=iterations, dklen=32)

    plaintext = private_key.to_bytes(PRIVKEY_LEN_BYTES, "big")
    iv = os.urandom(GCM_IV_LEN)
    ciphertext, tag = gost_gcm_encrypt(plaintext, key, iv)

    return {
        "kdf": "pbkdf2_hmac_sha256",
        "iterations": iterations,
        "salt": _b64e(salt),
        "iv": _b64e(iv),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
    }


def decrypt_private_key(enc_record: Dict[str, Any], password: str) -> int:
    if enc_record.get("kdf") != "pbkdf2_hmac_sha256":
        raise ValueError("Unsupported KDF")

    iterations = int(enc_record["iterations"])
    salt = _b64d(enc_record["salt"])
    iv = _b64d(enc_record["iv"])
    ciphertext = _b64d(enc_record["ciphertext"])
    tag = _b64d(enc_record["tag"])

    key = pbkdf2_sha256(password, salt, iterations=iterations, dklen=32)
    plaintext = gost_gcm_decrypt(ciphertext, key, iv, tag)
    if len(plaintext) != PRIVKEY_LEN_BYTES:
        raise ValueError("Invalid private key length")
    return int.from_bytes(plaintext, "big")


def create_user_store(
    path: str,
    *,
    alice_password: str,
    bob_password: str,
    overwrite: bool = False,
    iterations: int = PBKDF2_DEFAULT_ITERATIONS,
) -> Dict[str, Any]:
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"User store already exists at: {path}")

    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    store: Dict[str, Any] = {
        "version": 1,
        "users": {
            "alice": {
                "public_key": [alice_pub[0], alice_pub[1]],
                "password": make_password_record(alice_password, iterations=iterations),
                "private_key_enc": encrypt_private_key(alice_priv, alice_password, iterations=iterations),
            },
            "bob": {
                "public_key": [bob_pub[0], bob_pub[1]],
                "password": make_password_record(bob_password, iterations=iterations),
                "private_key_enc": encrypt_private_key(bob_priv, bob_password, iterations=iterations),
            },
        },
    }

    save_user_store(path, store)
    return store


def save_user_store(path: str, store: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp_path, path)


def load_user_store(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        store = json.load(f)
    if store.get("version") != 1:
        raise ValueError("Unsupported user store version")
    return store


def get_public_key(store: Dict[str, Any], username: str) -> Tuple[int, int]:
    user = store["users"][username]
    pub = user["public_key"]
    return int(pub[0]), int(pub[1])


def unlock_private_key(store: Dict[str, Any], username: str, password: str) -> int:
    user = store["users"][username]
    if not verify_password(user["password"], password):
        raise ValueError("Invalid password")
    return decrypt_private_key(user["private_key_enc"], password)
