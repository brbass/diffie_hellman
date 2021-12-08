import itertools, sympy

##################################
# Simple example of key exchange #
##################################

bounds = [1e2, 1e3]
public_key = sympy.randprime(bounds[0], bounds[1])
print('setting public key to {}'.format(public_key))
public_base = sympy.randprime(2, 8)
print('setting public base to {}'.format(public_base))
print

class Person:
    def __init__(self, name):
        self.name = name
        return
    def set_private_key(self, key):
        self.private_key = key
        print('setting private key for {} to {}'.format(self.name, key))
        self.calculate_modified_key()
    def calculate_modified_key(self):
        self.modified_key = pow(public_base, self.private_key, public_key)
        print('calculating modified key for {}:\n\tpublic_base ^ private_key_{} % public_key = {}^{} % {} = {}\n'.format(self.name, self.name, public_base, self.private_key, public_key, self.modified_key))
        return
    def calculate_mutual_key(self, key, name):
        self.mutual_key = pow(key, self.private_key, public_key)
        print('calculating mutual key for {} and {}:\n\tmodified_key_{} ^ private_key_{} % public_key = {}^{} % {} = {}\n'.format(self.name, name, name, self.name, key, self.private_key, public_key, self.mutual_key))
        return

people = [Person(p) for p in ['alice', 'bob', 'cat', 'doug']]
for p in people:
    p.set_private_key(sympy.randprime(bounds[0], bounds[1]))
print

pairs = [c for c in itertools.combinations(people, 2)]
for r in pairs:
    for p1, p2 in zip(r, reversed(r)):
        p1.calculate_mutual_key(p2.modified_key, p2.name)
