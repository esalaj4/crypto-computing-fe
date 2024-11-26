import random
import numpy as np
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
    return p,q


def get_large_prime(bits:int):
    """
    outputs a large prime number with specified bit size
    bits = sec_param grom generate_group
    """
    return randprime(2**(bits-1), 2**bits) # random prime number in that range

def get_group_generator(p: int):
    """
    finds a primitive root(group generator) for Z_p*
    """
    for g in range(2, p):
        if pow(g, (p - 1) // 2, p) != 1:  # Check if g is a generator
            return g
    raise ValueError("No generator found")

def get_random_generator(group):
    return group.randomGen()

def get_modulus(element: int, modulus: int) -> int:
    """
    Returns the modulus of the modular expression.

    Args:
        element (int): Group element in modular arithmetic.
        modulus (int): Modulus of the group.

    Returns:
        int: The modulus of the modular expression.
    """
    return modulus

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

def get_random_from_Zl(l: int) -> int:
    """Returns a cryptographically secure random number modulo l."""
    return random.SystemRandom().randrange(1, l)

def inner_product(a: List[int], b: List[int]) -> int:
    """
    Computes the inner product of two vectors.

    Args:
        a (List[int]): First vector.
        b (List[int]): Second vector.

    Returns:
        int: Inner product of the two vectors.
    """
    if len(a) != len(b):
        raise ValueError("Vector size mismatch")
    return sum(x * y for x, y in zip(a, b))


def inner_product_modulo(a: List[int], b: List[int], mod: int) -> int:
    """Computes the inner product of two vectors modulo mod."""
    if len(a) != len(b):
        raise ValueError("Vector size mismatch")
    return sum((x * y) % mod for x, y in zip(a, b)) % mod

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




def discrete_log(a:int, b:int, mod:int, limit:int = 100000) -> int:
    for i in range(limit): # to limit the search 
        if pow(a, i, mod) == b:
            return i
    return None

def sample_random_matrix_mod(size: tuple, mod: int) -> np.ndarray:
    """Generates a random matrix with elements modulo mod."""
    return np.random.randint(low=0, high=mod, size=size, dtype=np.int64)


def multiply_matrices_mod(A: np.ndarray, B: np.ndarray, mod: int) -> np.ndarray:
    """Multiplies two matrices modulo mod."""
    return np.dot(A, B) % mod