from typing import Dict, List, Union, Tuple
from helper_function import *

IntegerGroupElement = Union[GroupElement, int]

def set_up(security_parameter: int, vector_length: int) -> Tuple[Dict[str, object], List[int]]:
    """
    Initializes the system by generating the master public and secret keys.
    Returns the master public key (mpk) and master secret key (msk) as vectors of group elements.
    """
    p, g_value = generate_group(security_parameter)
    g = GroupElement(g_value, p)

    # Secret keys: random integers modulo p
    s = [random.randint(1, p - 1) for _ in range(vector_length)]

    # Public keys: h[i] = g^s[i]
    h = [g ** s[i] for i in range(vector_length)]

    # Return the master keys
    mpk = {'group': {'p': p, 'g': g}, 'h': h}
    msk = s
    return mpk, msk


def encrypt(mpk: dict, x: List[int]) -> Dict[str, List[IntegerGroupElement]]:
    """
    Encrypts the integer vector x using the master public key (mpk).
    Returns the ciphertext.
    """
    if len(x) > len(mpk['h']):
        raise ValueError("Vector x is too long for the given master public key.")

    p = mpk['group']['p']
    g = mpk['group']['g']
    r = random.randint(1, p - 1)

    # Ciphertext: ct_0 = g^r, ct[i] = h[i]^r * g^x[i]
    ct_0 = g ** r
    x = reduce_vector_mod(x, p)
    ct = [(mpk['h'][i] ** r) * (g ** x[i]) for i in range(len(x))]

    return {'ct0': ct_0, 'ct': ct}


def get_functional_key(mpk: dict, msk: List[IntegerGroupElement], y: List[int]) -> int:
    """
    Derives the functional key for calculating the inner product with vector y.
    """
    if len(y) > len(msk):
        raise ValueError(f'Vector {y} too long for the configured FE')
    y = reduce_vector_mod(y, mpk['group']['p'])
    return inner_product_group_vector(msk, y)


def decrypt(mpk: dict, ciphertext: Dict[str, List[GroupElement]], sk_y: int, y: List[int], limit: int) -> int:
    """
    Decrypts the ciphertext and returns the inner product of vectors x and y,
    if it is within the provided limit.
    """
    ct_0 = ciphertext['ct0']
    ct = ciphertext['ct']
    y = reduce_vector_mod(y, mpk['group']['p'])

    # Compute t[i] = ct[i]^y[i]
    t = [ct[i] ** y[i] for i in range(len(ct))]

    # Compute product of t[i] values
    product = t[0]
    for ti in t[1:]:
        product *= ti

    # Intermediate value: product / ct_0^sk_y
    inverse_ct_0_sk_y = ct_0 ** (-sk_y)
    intermediate = product * inverse_ct_0_sk_y

    # Extract integer representation of the intermediate result
    pi = get_int(intermediate)

    # Solve for the inner product using discrete logarithm
    g = get_int(mpk['group']['g'])
    return discrete_log(g, pi, mpk['group']['p'], limit)


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


def __main__():
    """
    Main function to test the functional encryption setup.
    """
    print("******** FUNCTIONAL ENCRYPTION ********")
    security_parameter = 128
    vector_length = 8

    mpk, msk = set_up(security_parameter, vector_length)

    test_cases = [
        (0, 0), (1, 0), (2, 1), (3, 7),
        (4, 5), (7, 2), (6, 6), (5, 4)
    ]

    for alice_input, bob_input in test_cases:
        print(f"Testing Alice: {alice_input}, Bob: {bob_input}")
        alice_new, bob_new = process_input(alice_input, bob_input)
        ciphertext = encrypt(mpk, alice_new)
        sk_y = get_functional_key(mpk, msk, bob_new)
        result = decrypt(mpk, ciphertext, sk_y, bob_new, limit=1000)
        result = result % 2
        # Compare the output with the computed boolean formula
        assert result == blood_type_compatibility_formula(alice_input, bob_input), f"Test failed for Alice: {alice_input}, Bob: {bob_input}"
    print("All test cases passed!")

if __name__ == "__main__":
    __main__()
