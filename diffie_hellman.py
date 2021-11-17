import argparse, sympy

# Steps to run this:
# 1. Generate private and public keys
#    python diffie-hellman.py -r -u
# 2. Give public key to other person and have them set their public key to agree (or vice versa)
#    python diffie-hellman.py -s 339124852213127435713
# 3. Calculate colored public key to share
#    python diffie-hellman.py 


# The bounds for the public and private key
# These should be very large and prime
large_bounds = [1e300, 1e301]

# Fix the public base for simplicity
# This is prime and commonly small, like 2 or 3
public_base = 2

# Set filenames for public and private keys
private_key_filename = 'private_key'
public_key_filename = 'public_key'

# Generate a random prime within the given bounds (inclusive)
def get_prime(bounds):
    return sympy.randprime(bounds[0]-1, bounds[1])

# Generate a key and save to file
def set_key(key, filename):
    with open(filename, 'w') as f:
        f.write(str(key))
def generate_key(bounds, filename):
    set_key(get_prime(bounds), filename)
    return

# Make getting the keys simple
def get_key(filename):
    with open(filename, 'r') as f:
        key = int(f.read())
    return key

# Make sure our public and private keys differ
def check_keys():
    private_key = get_key(private_key_filename)
    public_key = get_key(public_key_filename)
    if private_key == public_key:
        print("WARNING: public and private keys are equal")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Key generation arguments
    parser.add_argument('-r', '--generate_private_key', action='store_true',
                        help='generate new private key')
    parser.add_argument('-u', '--generate_public_key', action='store_true',
                        help='generate new public key')
    parser.add_argument('-s', '--set_public_key', type=int, nargs=1, default=-1,
                        help='set public key')
    args = parser.parse_args()

    # Private key
    if args.generate_private_key:
        generate_key(large_bounds, private_key_filename)
        
    # Public key
    if args.generate_public_key:
        generate_key(large_bounds, public_key_filename)
    if args.set_public_key != -1:
        set_key(args.set_public_key, public_key_filename)

    # Check keys
    check_keys()

    
