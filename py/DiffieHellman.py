#%%:
import random

def generate_secret(prime):
    return random.randint(0, prime)

def diffie_hellman_public(prime, alfa, source_secret):
    return (alfa ** source_secret) % prime

def diffie_hellman_key(prime, source_secret, destination_public_key):
    return (destination_public_key ** source_secret) % prime
