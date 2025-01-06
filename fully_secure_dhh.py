from typing import List, Dict, Union
from helper_function import *
import random
import numpy as np

IntegerGroupElement = Union[GroupElement, int]

def set_up(security_parameter: int, vector_length: int) -> Tuple[Dict, Dict]:
    """Sets up parameters and generates master public and secret keys."""
    p, g_value1, g_value2 = generate_group_fully_secured(security_parameter)
    gen1, gen2 = GroupElement(g_value1, p), GroupElement(g_value2, p)

    s, t = [random.randint(1, p - 1) for _ in range(vector_length)], [random.randint(1, p - 1) for _ in range(vector_length)]
    h = [(gen1 ** s[i]) * (gen2 ** t[i]) for i in range(vector_length)]
    return {'gen1': gen1, 'gen2': gen2, 'p': p, 'h': h}, {'s': s, 't': t}

def get_functional_key(mpk: Dict, msk: Dict, y: List[int]) -> Dict:
    """Derives the functional key for inner product calculation with vector y."""
    y = reduce_vector_mod(y, mpk['p'])
    return {'s_y': inner_product_group_vector(msk['s'], y), 't_y': inner_product_group_vector(msk['t'], y)}

def encrypt(mpk: Dict, x: List[int]) -> Dict:
    """Encrypts the integer vector x."""
    x = reduce_vector_mod(x, mpk['p'])
    r = random.randint(1, mpk['p'] - 1)
    return {
        'c': mpk['gen1'] ** r,
        'd': mpk['gen2'] ** r,
        'e': [(mpk['gen1'] ** x[i]) * (mpk['h'][i] ** r) for i in range(len(x))]
    }

def decrypt(mpk: Dict, func_key: Dict, ciphertext: Dict, y: List[int], limit: int) -> int:
    """Decrypts the ciphertext using the functional key and vector y."""
    e = ciphertext['e']
    intermediate = np.prod([e[i] ** y[i] for i in range(len(y))]) / (
        ciphertext['c'] ** func_key['s_y'] * ciphertext['d'] ** func_key['t_y']
    )
    return discrete_log(get_int(mpk['gen1']), get_int(intermediate), mpk['p'], limit)

def process_input(input_alice: int, input_bob: int) -> Tuple[List[int], List[int]]:
    """
    Encodes the inputs for Alice and Bob into feature vectors.
    """
    x2, x1, x0 = int_bit(input_alice, 2), int_bit(input_alice, 1), int_bit(input_alice, 0)
    y2, y1, y0 = int_bit(input_bob, 2), int_bit(input_bob, 1), int_bit(input_bob, 0)

    # Construct feature vectors for Alice and Bob
    x = [1, -(~x2), -(~x1), (~x1) * (~x2), -(~x0), (~x0) * (~x2), (~x0) * (~x1), -(~x0) * (~x1) * (~x2)]
    y = [1, y2, y1, y1 * y2, y0, y0 * y2, y0 * y1, y0 * y1 * y2]

    return x, y

test_cases = [
    (0, 0), (1, 0), (2, 1), (3, 7),
    (4, 5), (7, 2), (6, 6), (5, 4)]


for alice_input, bob_input in test_cases:
    print(f"Testing Alice: {alice_input}, Bob: {bob_input}")
    alice_new, bob_new = process_input(alice_input, bob_input)
    mpk, msk = set_up(1024, len(alice_new))
    ciphertext = encrypt(mpk,alice_new)
    func_key = get_functional_key(mpk, msk, bob_new)
    final_result = decrypt(mpk, func_key, ciphertext, bob_new, 200)
    result = result % 2
        # Compare the output with the computed boolean formula
    assert result == blood_type_compatibility_formula(alice_input, bob_input), f"Test failed for Alice: {alice_input}, Bob: {bob_input}"
    print("All test cases passed!")
