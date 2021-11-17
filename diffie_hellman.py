import argparse, os, sympy, sys
import numpy as np

# Steps to run:
# 1. Generate private and public keys
#    python diffie-hellman.py -r -u
# 2. Give public key to partner and have them set their public key to agree (or vice versa)
#    python diffie-hellman.py -s 339124852213127435713
# 3. Calculate modified public key
#    python diffie-hellman.py -c
# 4. Send this modified public key to partner and put in their modified public key
#    python diffie-hellman.py -t 'erica' -m 896472694141726829263
# 5. Encrypt a message and send it to partner
#    python diffie-hellman.py -t 'erica' -e 'Very secret message.'
# 6. Decrypt a message from partner
#    python diffie-hellman.py -t 'erica' -e asdfkajweioisxcvjk23i

###################################
# Encryption using Diffie-Hellman #
###################################
# The bounds for the public and private key
# These should be very large and prime
large_bounds = [1e300, 1e301]

# Fix the public base for simplicity
# This is prime and commonly small, like 2 or 3
public_base = 2

# Set filenames for public and private keys
key_folder = 'keys'
private_filename = 'private_key'
public_filename = 'public_key'
modified_filename = 'modified_key'
    
# Generate a random prime within the given bounds (inclusive)
def get_prime(bounds):
    return sympy.randprime(bounds[0]-1, bounds[1])

# Save a key to file
def save_key(key, filename):
    if not os.path.isdir(key_folder):
        os.mkdir(key_folder)
    with open(os.path.join(key_folder, filename), 'w') as f:
        f.write(str(key))

# Return the key in the given file
def get_key(filename):
    try:
        with open('keys/{}'.format(filename), 'r') as f:
            key = int(f.read())
    except:
        raise IOError, filename + " not set"
    return key

# Generate and save a key
def generate_key(bounds, filename):
    print("generating {}".format(filename))
    save_key(get_prime(bounds), filename)
    return

# Print a key
def print_key(filename):
    key = get_key(filename)
    print("{}:\n{}".format(filename, key))
    
# Make sure our keys follow good practices
def check_keys(filenames):
    # Check for duplicate keys
    keys = [get_key(f) for f in filenames]
    if (len(keys) > len(set(keys))):
        print("WARNING: public and private keys are equal")
        
    # Make sure our keys are prime
    for k, f in zip(keys, filenames):
        if not sympy.isprime(k):
            print("WARNING: {} is not prime".format(f))

# Calculate a modified key to pass publicly
def calculate_modified_key():
    print('generating {}'.format(modified_filename))
    private_key = get_key(private_filename)
    public_key = get_key(public_filename)
    modified_key = pow(public_base, private_key, public_key)
    save_key(modified_key, modified_filename)

# Get filename for modified key from someone else
def get_modified_filename(partner):
    return '{}_{}'.format(modified_filename, partner)

# Get filename for private key for someone else
def get_private_filename(partner):
    return '{}_{}'.format(private_filename, partner)

# Calculate a shared private key
def calculate_shared_private_key(partner):
    print('generating {}'.format(get_private_filename(partner)))
    private_key = get_key(private_filename)
    public_key = get_key(public_filename)
    shared_modified_key = get_key(get_modified_filename(partner))
    shared_private_key = pow(shared_modified_key, private_key, public_key)
    save_key(shared_private_key, get_private_filename(partner))

################################################################
# Encryption and decryption using simple matrix multiplication #
################################################################
# Convert strings to lists of numbers and vice versa
def string_to_numbers(string):
    vals = [ord(s) for s in string.decode()]
    return vals
def numbers_to_string(number):
    val = ''.join(chr(n).encode() for n in number).encode()
    return val

# Get encryption matrix from key
def get_encryption_matrix(key):
    elements = [str(i) for i in str(key)]
    num_int = len(elements)
    rank = int(np.floor(np.sqrt(num_int)))
    matrix = np.empty((rank, rank), dtype=int)
    for i in range(rank):
        for j in range(rank):
            matrix[i][j] = elements[i + rank * j]
    return matrix

# Get decryption matrix from key
def get_decryption_matrix(key):
    return np.linalg.inv(get_encryption_matrix(key))

# Encrypt a message
def encrypt_message(partner, message):
    matrix = get_encryption_matrix(get_key(get_private_filename(partner)))
    rank = np.linalg.matrix_rank(matrix)
    num_blocks = int(np.ceil(1.0 * len(message) / rank))
    padded_message = message
    for i in range(len(message), rank * num_blocks):
        padded_message += ' '
    encoded_message = string_to_numbers(padded_message)
    encrypted_numbers = np.empty(rank * num_blocks, dtype=int)
    rhs = np.empty(rank, dtype=int)
    for b in range(num_blocks):
        for i in range(rank):
            rhs[i] = encoded_message[i + rank * b]
        lhs = np.dot(matrix, rhs)
        for i in range(rank):
            encrypted_numbers[i + rank * b] = lhs[i]
    return encrypted_numbers

# Decrypt a message
def decrypt_message(partner, message):
    key = get_key(get_private_filename(partner))
    matrix = get_decryption_matrix(get_key(get_private_filename(partner)))
    rank = np.linalg.matrix_rank(matrix)
    if len(message) % rank != 0:
        print(len(message), rank)
        raise ValueError, "message is incorrect length"
    num_blocks = len(message) / rank
    decrypted_message = ''
    rhs = np.empty(rank, dtype=int)
    for b in range(num_blocks):
        for i in range(rank):
            rhs[i] = message[i + rank * b]
        lhs = np.round(np.dot(matrix, rhs))
        lhs = [int(i) for i in lhs]
        decrypted_message += numbers_to_string(lhs)
    return decrypted_message

#####################
# Key related stuff #
#####################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--generate_private_key', action='store_true',
                        help='generate new private key')
    parser.add_argument('-u', '--generate_public_key', action='store_true',
                        help='generate new public key')
    parser.add_argument('-s', '--set_public_key', type=int, nargs='?',
                        help='set public key')
    parser.add_argument('-c', '--calculate_modified_key', action='store_true',
                        help='calculate modified public key')
    parser.add_argument('-t', '--partner', type=str, nargs='?',
                        help='specify recipient of message or key')
    parser.add_argument('-m', '--set_modified_key', nargs='?',
                        help='set modified key from partner')
    parser.add_argument('-e', '--encrypt_message', type=str, nargs='?',
                        help='message that will be encrypted')
    parser.add_argument('-d', '--decrypt_message', type=str, nargs='?',
                        help='message that will be decrypted')
    args = parser.parse_args()

    # Generate and set keys
    generating = False
    if args.generate_private_key:
        generate_key(large_bounds, private_filename)
        generating = True
        
    if args.set_public_key is not None:
        save_key(args.set_public_key, public_filename)
        generating = True
    elif args.generate_public_key:
        generate_key(large_bounds, public_filename)
        generating = True
        
    # Check keys once they are generated and set
    check_keys([public_filename, private_filename])
    
    # Calculate modified key
    if args.calculate_modified_key or generating:
        calculate_modified_key()
        generating = True
        
    # If we have generated keys, then we need to quit so we can trade keys
    if generating:
        print('exiting so keys can be traded')
        quit()
        
    # Set modified key from partner
    if args.set_modified_key is not None:
        if args.partner is None:
            raise IOError, 'must specify partner to set their modified key'
        save_key(args.set_modified_key, get_modified_filename(args.partner))
        calculate_shared_private_key(args.partner)

    # Encrypt a message to partner
    if args.encrypt_message is not None:
        if args.partner is None:
            raise IOError, 'must specify partner to encrypt message'
        print(encrypt_message(args.partner, args.encrypt_message))

    # Decrypt a message from partner
    if args.decrypt_message is not None:
        if args.partner is None:
            raise IOError, 'must specify partner to decrypt message'
        print(decrypt_message(args.partner, np.array(args.encrypt_message)))
