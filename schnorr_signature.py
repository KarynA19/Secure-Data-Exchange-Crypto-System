import hashlib
import secrets
from EllipticCurveDiffieHellman import curve, base_point, curve_order, prime_modulus

def hash_data(R, P, message):
    """
    Hashes the point R, public key P, and message to create a scalar.
    e = H(R || P || m)
    """
    if R is None or P is None:
        raise ValueError("Points cannot be None for hashing.")
    
    # Convert coordinates to bytes (32 bytes for 256-bit curve)
    # R = (x, y)
    r_x_bytes = R[0].to_bytes(32, 'big')
    r_y_bytes = R[1].to_bytes(32, 'big')
    
    p_x_bytes = P[0].to_bytes(32, 'big')
    p_y_bytes = P[1].to_bytes(32, 'big')
    
    if isinstance(message, str):
        msg_bytes = message.encode('utf-8')
    elif isinstance(message, bytes):
        msg_bytes = message
    else:
        # Try to convert integer message to bytes if applicable, or str
        msg_bytes = str(message).encode('utf-8')
        
    data = r_x_bytes + r_y_bytes + p_x_bytes + p_y_bytes + msg_bytes
    hash_value = hashlib.sha256(data).digest()
    
    # Convert hash to integer
    return int.from_bytes(hash_value, 'big')

def sign(private_key, message):
    """
    Generates a Schnorr signature for the given message using the private key.
    Returns (R, s).
    """
    if not (1 <= private_key < curve_order):
        raise ValueError("Private key must be in the range [1, curve_order - 1]")

    # 1. Choose a random nonce k in [1, curve_order - 1]
    k = secrets.randbelow(curve_order)
    while k == 0:
        k = secrets.randbelow(curve_order)
        
    # 2. Calculate R = k * G
    R = curve.multiply_point_on_curve(k, base_point)
    
    # Calculate Public Key P = x * G (needed for the hash)
    P = curve.multiply_point_on_curve(private_key, base_point)
    
    # 3. Calculate e = H(R || P || m) mod n
    e = hash_data(R, P, message) % curve_order
    
    # 4. Calculate s = (k + e * x) mod n
    s = (k + e * private_key) % curve_order
    
    return (R, s)

def verify(public_key, message, signature):
    """
    Verifies a Schnorr signature (R, s) for the given message and public key.
    Returns True if valid, False otherwise.
    """
    R, s = signature
    
    if R is None:
        return False
        
    if not (0 < s < curve_order):
        return False
        
    if public_key is None:
        return False

    # Check if public key is on the curve (Optional but recommended)
    # y^2 = x^3 + ax + b mod p
    val_lhs = (public_key[1] ** 2) % prime_modulus
    val_rhs = (public_key[0] ** 3 + curve.coeff_a * public_key[0] + curve.coeff_b) % prime_modulus
    if val_lhs != val_rhs:
        return False
        
    # 1. Calculate e = H(R || P || m) mod n
    e = hash_data(R, public_key, message) % curve_order
    
    # 2. Compute s * G
    sg = curve.multiply_point_on_curve(s, base_point)
    
    # 3. Compute R + e * P
    ep = curve.multiply_point_on_curve(e, public_key)
    rhs = curve.add_points_to_curve(R, ep)
    
    # 4. Check if s * G == R + e * P
    return sg == rhs