import random
from typing import List
from sympy import randprime
from typing import Tuple

class GroupElement:
    def __init__(self, value: int, modulus: int):
        self.value = value % modulus
        self.modulus = modulus

    def __pow__(self, exponent: int):
        return GroupElement(pow(self.value, exponent, self.modulus), self.modulus)

    def __mul__(self, other):
        if isinstance(other, GroupElement) and self.modulus == other.modulus:
            return GroupElement((self.value * other.value) % self.modulus, self.modulus)
        raise ValueError("Incompatible group elements for multiplication.")

    def __repr__(self):
        return f"GroupElement({self.value}, mod={self.modulus})"


def generate_group(sec_param) -> Tuple[int, int]:
    """
    Generates a Schnorr-like group (Z_p*) where p is a prime of size `sec_param`.
    sec_param: int
    output: (p,q) = (int,int), a tuple where p is a prime and q is a group generator
    """
    p = get_large_prime(sec_param)
    q = get_group_generator(p)
    return p, q


def get_large_prime(bits: int):
    """
    outputs a large prime number with specified bit size
    bits = sec_param grom generate_group
    """
    return randprime(2 ** (bits - 1), 2 ** bits)  # random prime number in that range


def get_group_generator(p: int):
    """
    finds a primitive root(group generator) for Z_p*
    """
    for g in range(2, p):
        if pow(g, (p - 1) // 2, p) != 1:  # Check if g is a generator
            return g
    raise ValueError("No generator found")


def reduce_vector_mod(vector: List[int], mod: int) -> List[int]:
    """Reduces all elements of a vector modulo mod

    Args:
        vector (List[int]): list representation of vector
        mod (int): modulus

    Returns:
        List[int]: vector with reduced elements
    """
    reduced = []
    for i in range(len(vector)):
        reduced.append(vector[i] % mod)
    return reduced

# generate a cryptographically secure random number that is modulo l
def get_random_from_Zl(l: int) -> int:
    """Returns a cryptographically secure random number modulo l."""
    return random.SystemRandom().randrange(1, l)

def inner_product_group_vector(a: List[GroupElement], b: List[int]) -> int:
    """
    Calculates the inner product of a group element vector and an integer vector.

    Args:
        a (List[GroupElement]): Vector of group elements.
        b (List[int]): Vector of integers.

    Returns:
        int: Inner product of the two vectors.

    Raises:
        ValueError: If the lengths of the two vectors do not match.
    """
    if len(a) != len(b):
        raise ValueError("Vector size mismatch!")

    # Compute the inner product
    inner = sum(get_int(element) * b[i] for i, element in enumerate(a))
    return inner

def get_int(element):
    """
    Retrieves the integer value of a group element or returns the integer itself.

    Args:
        element (GroupElement or int): Group element or integer.

    Returns:
        int: Integer value of the group element or the integer itself.
    """
    if isinstance(element, GroupElement):
        return element.value
    elif isinstance(element, int):
        return element
    else:
        raise ValueError(f"Unexpected type in get_int: {type(element)} - Value: {element}")

def discrete_log(a: int, b: int, mod: int, limit: int = 100000) -> int:
    """
    Computes the discrete logarithm: finds the smallest integer `i` such that (a^i) % mod == b.

    Args:
        a (int): The base of the exponentiation (generator of the group).
        b (int): The target value (result of the exponentiation modulo `mod`).
        mod (int): The modulus of the group (prime number).
        limit (int, optional): The maximum number of iterations to search for `i`. Defaults to 100000.

    Returns:
        int: The discrete logarithm `i` if found, or None if no such `i` exists within the limit.
    """
    for i in range(limit):  # Iterate up to the limit to search for the solution
        # Compute a^i % mod and check if it equals b
        if pow(a, i, mod) == b:
            return i  # Return the solution if found
    return None  # Return None if no solution is found within the limit
# Extracts the i-th bit from a number
def int_bit(num, i):
    """
    Extracts the i-th bit (0-indexed) from the binary representation of a given integer.

    Args:
        num (int): The integer whose bit is to be extracted.
        i (int): The index of the bit to extract (0 = least significant bit).

    Returns:
        int: The value of the i-th bit (either 0 or 1).
    """
    return (num >> i) & 1  # Right-shift `num` by `i` bits and isolate the least significant bit

def blood_type_compatibility_formula(input_alice, input_bob):
    """
    Computes blood type compatibility between Alice and Bob using a Boolean formula.

    Args:
        input_alice (int): Encoded input representing Alice's blood type.
        input_bob (int): Encoded input representing Bob's blood type.

    Returns:
        int: 1 if Alice and Bob are compatible, 0 otherwise.
    """
    # Extract the individual bits of Alice's input
    x2, x1, x0 = int_bit(input_alice, 2), int_bit(input_alice, 1), int_bit(input_alice, 0)

    # Extract the individual bits of Bob's input
    y2, y1, y0 = int_bit(input_bob, 2), int_bit(input_bob, 1), int_bit(input_bob, 0)

    # Boolean compatibility formula:
    real_result = (1 ^ (y0 & (1 ^ x0))) & (1 ^ (y1 & (1 ^ x1))) & (1 ^ (y2 & (1 ^ x2)))

    return real_result  # Return 1 (compatible) or 0 (not compatible)

