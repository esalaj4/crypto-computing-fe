from typing import Dict, List, Union, Tuple
from helperFunction import *

IntegerGroupElement = Union[GroupElement, int]

def set_up(security_parameter: int, vector_length: int) -> Tuple[Dict[str, object], List[int]]:  # type: ignore
    """
     Samples an integer group of order p, where p is a prime number of
    bit-size equal to security_parameter. Returns master public key and master secret
    key as vectors of group elements.
    """
    p, g_value = generate_group(security_parameter)
    g = GroupElement(g_value, p)

    # Generate secret keys (random integers modulo p)
    s = [random.randint(1, p - 1) for _ in range(vector_length)]

    # Generate public keys h[i] = g^s[i]
    h = [g ** s[i] for i in range(vector_length)]

    # Master public key and secret key
    mpk = {'group': {'p': p, 'g': g}, 'h': h}
    msk = s
    return mpk, msk


def encrypt(mpk: dict, x: List[int]) -> Dict[str, List[IntegerGroupElement]]:
    """Encrypts integer vector x

    Args:
        mpk (dict): master public key
        x (List[int]): integer vector to be encrypted

    Returns:
        Dict[str, List[IntegerGroupElement]]: ciphertext corresponding to vector x
    """
    if len(x) > len(mpk['h']):
        raise ValueError("Vector x is too long for the given master public key.")

    # Generate random r in [1, p-1]
    p = mpk['group']['p']
    g = mpk['group']['g']  # Fix: Access g correctly
    r = random.randint(1, p - 1)

    # Compute ct_0 = g^r
    ct_0 = g ** r

    # Reduce vector x modulo p
    x = reduce_vector_mod(x, p)

    # Compute ct[i] = h[i]^r * g^x[i]
    ct = [(mpk['h'][i] ** r) * (g ** x[i]) for i in range(len(x))]

    ciphertext = {'ct0': ct_0, 'ct': ct}
    return ciphertext


def get_functional_key(mpk: dict, msk: List[IntegerGroupElement], y: List[int]) -> int:
    """Derives functional key for calculating inner product with vector y

    Args:
        mpk (dict): master public key
        msk (List[IntegerGroupElement]): master secret key
        y (List[int]): vector for which the functional key should be calculatd

    Raises:
        WrongVectorSizeError: if the vector y is longer than the supported vector length

    Returns:
        int: Functional key corresponding to vector y
    """
    if len(y) > len(msk):
        raise ValueError(f'Vector {y} too long for the configured FE')
    y = reduce_vector_mod(y, mpk['group']['p'])
    return inner_product_group_vector(msk, y)


def decrypt(
        mpk: dict,
        ciphertext: Dict[str, List[GroupElement]],
        sk_y: int,
        y: List[int],
        limit: int,
) -> int:
    """
    Returns the inner product of vector y and vector x encrypted in the ciphertext
    if it lies within the provided limit.

    Args:
        mpk (dict): Master public key.
        ciphertext (Dict[str, List[GroupElement]]): Ciphertext encrypting vector x.
        sk_y (int): Functional decryption key for vector y.
        y (List[int]): Vector y.
        limit (int): The upper bound for the inner product result.

    Returns:
        int: Inner product of x and y, or None if the inner product was not found
             within the limit.
    """
    # Extract components from ciphertext
    ct_0 = ciphertext['ct0']  # ct_0 = g^r
    ct = ciphertext['ct']  # ct[i] = h[i]^r * g^x[i]

    # Reduce vector y modulo p
    y = reduce_vector_mod(y, mpk['group']['p'])

    # Compute t[i] = ct[i]^y[i]
    t = [ct[i] ** y[i] for i in range(len(ct))]

    # Compute the product of all t[i] modulo the group modulus
    product = t[0]
    for ti in t[1:]:
        product *= ti

    if not isinstance(product, GroupElement):
        raise ValueError(f"Product is not a GroupElement: {type(product)}")

    # Compute intermediate value: product / ct_0^sk_y (mod group modulus)
    inverse_ct_0_sk_y = ct_0 ** (-sk_y)  # Modular inversion using exponentiation
    if not isinstance(inverse_ct_0_sk_y, GroupElement):
        raise ValueError("Modular inversion failed to produce a GroupElement.")

    intermediate = product * inverse_ct_0_sk_y
    if not isinstance(intermediate, GroupElement):
        raise ValueError("Intermediate value is not a GroupElement.")

    # Extract the integer representation of the intermediate result
    pi = get_int(intermediate)

    # Extract generator g's integer value
    g = get_int(mpk['group']['g'])

    # Solve for the inner product using discrete logarithm
    inner_prod = discrete_log(g, pi, mpk['group']['p'], limit)
    return inner_prod

## Expand the bloodtype compatiblity function
def process_input(input_alice: int, input_bob: int) -> Tuple[List[int], List[int]]:
    """
    Processes the inputs for Alice and Bob, encoding them into feature vectors.

    Args:
        input_alice (int): Input for Alice.
        input_bob (int): Input for Bob.

    Returns:
        Tuple[List[int], List[int]]: Two lists representing the encoded vectors for Alice and Bob.
    """
    # Encode the input for Alice
    x2, x1, x0 = int_bit(input_alice, 2), int_bit(input_alice, 1), int_bit(input_alice, 0)

    # Encode the input for Bob
    y2, y1, y0 = int_bit(input_bob, 2), int_bit(input_bob, 1), int_bit(input_bob, 0)

    # Construct the feature vectors
    x = [1, -(~x2), -(~x1), (~x1) * (~x2), -(~x0), (~x0) * (~x2), (~x0) * (~x1), -(~x0) * (~x1) * (~x2)]
    y = [1, y2, y1, y1 * y2, y0, y0 * y2, y0 * y1, y0 * y1 * y2]

    return x, y


def __main__():
    # Example group and encryption setup
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
        alice_new, bob_new = process_input(alice_input,bob_input)
        ciphertext = encrypt(mpk, alice_new)
        sk_y = get_functional_key(mpk, msk, bob_new)
        result = decrypt(mpk, ciphertext, sk_y, bob_new, limit=1000)
        result = result % 2
        # Compare the output of the protocol with the output computed using the boolean formula
        assert result == blood_type_compatibility_formula(alice_input, bob_input), f"Test failed for Alice: {alice_input}, Bob: {bob_input}"
    print("All test cases passed!")

if __name__ == "__main__":
    __main__()
