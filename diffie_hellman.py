import argparse, datetime, json, os, sympy
import numpy as np

##################################
# How to send encrypted messages #
##################################
# 1.  Generate public key (skip to use existing public key included in repo)
#         python diffie-hellman.py -u
# 2.  If generating a new public key, choose one of 2a or 2b
# 2a. Give public key to all partners and have them set it
# 2b. Set public key given by partner (will overwrite previous public key)
#         python diffie-hellman.py -s 339124852213127435713
# 3.  Generate private and modified keys 
#         python diffie-hellman.py -r -c 
# 4.  Send the modified public key to partner and put in their modified public key
#         python diffie-hellman.py -t 'erica' -m 896472694141726829263
# 5.  Encrypt a message and send it to partner
#         python diffie-hellman.py -t 'erica' -e 'Very secret message.'
# 6.  Decrypt a message from partner
#         python diffie-hellman.py -t 'erica' -e asdfkajweioisxcvjk23i

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
file_mode = False

def get_prime(bounds):
    """
    Generate a random prime within the given bounds (inclusive)
    
    :param bounds: Prime will be returned between these bounds
    """
    return sympy.randprime(bounds[0]-1, bounds[1])
def save_key(key, filename):
    """
    Save a key to file
    
    :param key: Key that is being saved
    :param filename: Location to store key to
    """
    if not os.path.isdir(key_folder):
        os.mkdir(key_folder)
    with open(os.path.join(key_folder, filename), 'w') as f:
        f.write(str(key))
    return

def get_key(filename):
    """
    Return the key in the given file
    
    :param filename: Location of key
    :return: Key
    """
    try:
        with open('keys/{}'.format(filename), 'r') as f:
            key = int(f.read())
    except:
        raise IOError(filename + " not set")
    return key

def generate_key(bounds, filename):
    """
    Generate and save a key

    :param bounds: Key will be between these numeric bounds
    :param filename: Location to store key to
    """
    print("generating {}".format(filename))
    save_key(get_prime(bounds), filename)
    return

def print_key(filename):
    """
    Print a key to terminal
    
    :param filename: Location of key
    """
    key = get_key(filename)
    print("{}:\n{}".format(filename, key))
    
def check_keys(filenames):
    """
    Make sure our keys follow good practices
    
    :param filenames: Key names to check
    :return: Whether keys exist and pass checks
    """
    # Check for duplicate keys
    try:
        keys = [get_key(f) for f in filenames]
    except Exception as e:
        print(e)
        return False
    if (len(keys) > len(set(keys))):
        print("WARNING: public and private keys are equal")
        
    # Make sure our keys are prime
    for k, f in zip(keys, filenames):
        if not sympy.isprime(k):
            print("WARNING: {} is not prime".format(f))
            
    return True

def calculate_modified_key():
    """Calculate a modified key to pass publicly"""
    print('generating {}'.format(modified_filename))
    private_key = get_key(private_filename)
    public_key = get_key(public_filename)
    modified_key = pow(public_base, private_key, public_key)
    save_key(modified_key, modified_filename)

def get_modified_filename(partner):
    """
    Get filename of modified key from someone else
    
    :param partner: Name of partner
    :return:  Filename of modified key for partner
    """
    return '{}_{}'.format(modified_filename, partner)

def get_private_filename(partner):
    """
    Get filename of private key from someone else
    
    :param partner: Name of partner
    :return:  Filename of private key for partner
    """
    return '{}_{}'.format(private_filename, partner)

def calculate_shared_private_key(partner):
    """
    Calculate a shared private key

    :param partner: Name of partner
    """
    print('generating {}'.format(get_private_filename(partner)))
    private_key = get_key(private_filename)
    public_key = get_key(public_filename)
    shared_modified_key = get_key(get_modified_filename(partner))
    shared_private_key = pow(shared_modified_key, private_key, public_key)
    save_key(shared_private_key, get_private_filename(partner))

################################################################
# Encryption and decryption using simple matrix multiplication #
################################################################
# Set filenames for messages
message_folder = 'messages'

def get_new_message_name(partner):
    """
    Get unique name for message

    :param partner: Person receiving message
    :return: Path of message
    """
    time = datetime.datetime.now()
    name = "{}_{}-{}-{}-{}-{}-{}".format(partner,
                                         time.year,
                                         time.month,
                                         time.day,
                                         time.hour,
                                         time.minute,
                                         time.second)
    return os.path.join(message_folder, name)

def save_message(partner, message):
    """
    Save message to file

    :param message: Any data structure to be saved
    :param partner: Person receiving message
    :return: Filename
    """
    if not os.path.isdir(message_folder):
        os.mkdir(message_folder)
    filename = get_new_message_name(partner)
    np.savetxt(filename, message, newline=' ', fmt='%d')
    # np.savez(filename, message)
    # with open(name, 'w') as f:
    #     json.dump(message, f)
    print("saving message to {}".format(filename))
    return filename

def load_message(filename):
    """
    Load message from file

    :param filename: Filename to load data from
    :return: Data that was stored
    """
    return np.loadtxt(filename)
    # with open(filename, 'r') as f:
    #     return json.load(f)

def string_to_numbers(string):
    """
    Convert a string to a list of numbers
    
    :param string: Message as string
    :return: Message as numbers
    """
    vals = [ord(s) for s in string]
    return vals
def numbers_to_string(numbers):
    """
    Convert a list of numbers to a string
    
    :param numbers: Message as numbers
    :return: Message as string
    """
    val = ''.join(chr(n).encode() for n in numbers).encode()
    return val

def get_encryption_matrix(key):
    """
    Get encryption matrix from key
    
    :param key: Encryption key
    :return: Encryption matrix
    """
    elements = [str(i) for i in str(key)]
    num_int = len(elements)
    rank = int(np.floor(np.sqrt(num_int)))
    matrix = np.empty((rank, rank), dtype=int)
    for i in range(rank):
        for j in range(rank):
            matrix[i][j] = elements[i + rank * j]
    return matrix

def get_decryption_matrix(key):
    """
    Get decryption matrix from key
    
    :param key: Encryption key
    :return: Decryption matrix
    """
    return np.linalg.inv(get_encryption_matrix(key))

def encrypt_message(partner, message):
    """
    Encrypt a message
    
    :param parner: Name of partner
    :param message: Message as string
    :return: Message as numbers
    """
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

def decrypt_message(partner, message):
    """
    Decrypt a message
    
    :param partner: Name of partner
    :param message: Message as numbers
    :return:  Message as string
    """
    encrypted_numbers = np.array(message)
    key = get_key(get_private_filename(partner))
    matrix = get_decryption_matrix(get_key(get_private_filename(partner)))
    rank = np.linalg.matrix_rank(matrix)
    if len(encrypted_numbers) % rank != 0:
        print(len(encrypted_numbers), rank)
        raise ValueError("message is incorrect length")
    num_blocks = len(encrypted_numbers) / rank
    decrypted_message = ''
    rhs = np.empty(rank, dtype=int)
    for b in range(num_blocks):
        for i in range(rank):
            rhs[i] = encrypted_numbers[i + rank * b]
        lhs = np.round(np.dot(matrix, rhs))
        lhs = [int(i) for i in lhs]
        decrypted_message += numbers_to_string(lhs)
    return decrypted_message

############################################
# Run the program if this script is called #
############################################
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
    if file_mode:
        parser.add_argument('-d', '--decrypt_message', type=str, nargs='?',
                            help='message that will be decrypted')
    else:
        parser.add_argument('-d', '--decrypt_message', type=int, nargs='*',
                            help='message that will be decrypted as a list of integers')
    args = parser.parse_args()

    # Generate and set keys
    generating = False
    if args.set_public_key is not None:
        save_key(args.set_public_key, public_filename)
        generating = True
    elif args.generate_public_key:
        generate_key(large_bounds, public_filename)
        generating = True
        
    if args.generate_private_key:
        generate_key(large_bounds, private_filename)
        generating = True
        
    # Check keys once they are generated and set
    if not check_keys([public_filename, private_filename]):
        quit()
    
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
            raise IOError('must specify partner to set their modified key')
        save_key(args.set_modified_key, get_modified_filename(args.partner))
        calculate_shared_private_key(args.partner)

    # Encrypt a message to partner
    if args.encrypt_message is not None:
        if args.partner is None:
            raise IOError('must specify partner to encrypt message')
        message = encrypt_message(args.partner, args.encrypt_message)
        if file_mode:
            filename = save_message(args.partner, message)
        else:
            print('encrypted message:')
            print(' '.join(str(m) for m in message))
            
    # Decrypt a message from partner
    if args.decrypt_message is not None:
        if args.partner is None:
            raise IOError('must specify partner to decrypt message')
        if file_mode:
            encrypted = load_message(args.decrypt_message)
            decrypted = decrypt_message(args.partner, encrypted)
        else:
            decrypted = decrypt_message(args.partner, args.decrypt_message)
        print('decrypted message:')
        print(decrypted)
        
        
