#######################################
### Elliptic Curve - Diffie Hellman ###
#######################################

# Class: EllipticCurveDiffieHellman
# Represents an elliptic curve over a finite field.
class EllipticCurveDiffieHellman:
    # Constructor: for EllipticCurveDiffieHellman class.
    def __init__(self, prime_modulus, coeff_a, coeff_b):
        self.prime_modulus = prime_modulus  # The prime modulus of the finite field.
        self.coeff_a = coeff_a              # Coefficient a
        self.coeff_b = coeff_b              # Coefficient b
        
    ####################################################
    ### Computational Functions for the ECDH Process ###
    ####################################################
    
    # Function: compute_modular_inverse
    # Computes the modular inverse using the Extended Euclidean Algorithm.
    # Solves the modular equation (value * x = 1 mod modulus)
    def compute_modular_inverse(self, value, modulus):
        if value == 0:
            raise ZeroDivisionError("Cannot compute modular inverse for 0.")
        elif value < 0:
            return modulus - self.compute_modular_inverse(-value, modulus) #Make value positive
        else:
            return self.extended_euclidean_algorithm(value, modulus)
            
    
    # Function: extended_euclidean_algorithm
    # Calculates the extended euclidean algorithm with given value and modulus.
    def extended_euclidean_algorithm(self, value, modulus):
        if modulus == 0:
            raise ValueError("Modulus must be greater than 0.")
            
        curr_s, prev_s = 0, 1
        curr_t, prev_t = 1, 0
        curr_r, prev_r = modulus, value
        while curr_r != 0:
            quotient = prev_r // curr_r
            prev_t, curr_t = curr_t, prev_t - quotient * curr_t
            prev_s, curr_s = curr_s, prev_s - quotient * curr_s
            prev_r, curr_r = curr_r, prev_r - quotient * curr_r
        
        # Check if GCD(value, modulus) is 1 (modular inverse exists)
        if prev_r != 1:
            raise ValueError(f"No modular inverse exists for {value} modulo {modulus}.")
        
        # Return the modular inverse, ensuring it is positive
        return prev_s % modulus
    
    # Function: add_points_to_curve
    # Adds two points on the elliptic curve.
    def add_points_to_curve(self, point1, point2):
        if point1 is None:
            return point2
        if point2 is None:
            return point1
        if point1 == point2:
            return self.double_points_on_curve(point1)
        if point1[0] == point2[0] and point1[1] != point2[1]:
            return None # Point at infinity.

        # Calculate the lambda
        slope = self.calculate_slope(point1, point2)
        x3 = (slope ** 2 - point1[0] - point2[0]) % self.prime_modulus
        y3 = (slope * (point1[0] - x3) - point1[1]) % self.prime_modulus
        return (x3, y3)
    
    # Function: double_points_on_curve
    # Doubles a point on the elliptic curve.
    def double_points_on_curve(self, point):
        if point is None:
            return None

        # Calculate the slope (lambda)
        slope = ((3 * point[0] ** 2 + self.coeff_a) * self.compute_modular_inverse(2 * point[1], self.prime_modulus)) % self.prime_modulus
        x = (slope ** 2 - 2 * point[0]) % self.prime_modulus
        y = (slope * (point[0] - x) - point[1]) % self.prime_modulus
        return (x, y)

    # Function: multiply_point_on_curve
    # Multiplies a point by a scalar using the double-and-add method.
    # Add each point to itself and add when the bit is 1
    def multiply_point_on_curve(self, scalar, point):
        result = None # point at infinity
        current = point

        while scalar:
            if scalar & 1:
                result = self.add_points_to_curve(result, current)
            current = self.double_points_on_curve(current)
            scalar >>= 1

        return result

    # Function: calculate_slope
    # Calculates the slope between two points.
    def calculate_slope(self, point1, point2):
        return ((point2[1] - point1[1]) * self.compute_modular_inverse(point2[0] - point1[0], self.prime_modulus)) % self.prime_modulus



####################################################

# SECP256k1 curve parameters
prime_modulus = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
coeff_a = 0
coeff_b = 7
base_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
base_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Create the elliptic curve and base point
curve = EllipticCurveDiffieHellman(prime_modulus, coeff_a, coeff_b)
base_point = (base_x, base_y)

# Function: getPublicKeysBasedOnPrivateKeys
# Returns the public keys based on given private keys.
def getPublicKeysBasedOnPrivateKeys(private_keys):
    return [curve.multiply_point_on_curve(private_key, base_point) for private_key in private_keys]