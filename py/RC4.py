#%%:

def RC4(key, text):
    # initialization
    key = [ord(c) for c in key]
    key_len = len(key)
    S = list(range(256))
    j = 0

    # initial permutation
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]

    # flow Generation
    i, j = 0, 0
    result = []
    for c in text:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(chr(ord(c) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(result)
