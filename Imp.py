from Perm import perm
import ascon

def s_split(s,r):
    sr = (s >> (320 - r))
    sc = (sr << (320 - r)) ^ s
    return sr, sc

def s_merge(sr,sc,r):
    s = (sr << (320-r)) ^ sc
    return s

def c_merge(c,r):
    y = 0
    for i in range(len(c)):
        y = y ^ (c[len(c) - i - 1] << (i * r))
    return y

def enc(K,N,A,P):

    #Initialisation
    iv = 0x80400c0600000000
    a = 0x0c
    b = 0x06
    r = 0x40
    k = 0x80
    s = (((iv << k) ^ K) << 128) ^ N  #K.bit_length()) ^ K #had set size to 128 based off test code.
    s = (perm(s, a) ^ ((0 << 320) ^ K))

    #Processing Associated data
    A = int.from_bytes(A, "big")
    Asplit = []
    print("Mine")
    print("A: ", hex(A))
    print("A bit length: ",A.bit_length())
    if A != 0:
        temp = ((A << 1) ^ 1) << (r-1-((A.bit_length())%r))
        print("Rate in bits: ", r)
        print("Padding length: ",(((0) ^ 1) << (r-1-((A.bit_length())%r))).bit_length())
        print("Padding: ", bin((((0) ^ 1) << (r-1-((A.bit_length())%r)))))
        print("Padded A length: ", temp.bit_length())
        print("Padded A: ",bin(temp))

        for i in range(int(temp.bit_length()/r)): #splitting A padded into blocks
            Asplit.insert(0, ((temp >> (i * r)) & 0xFFFFFFFFFFFFFFFF))

        for i in range(len(Asplit)):
            sr,sc = s_split(s,r)
            s = perm(((sr^Asplit[i])<<(320-r))^sc,b)
    s = s ^ 1
    from Perm import split
    print(split(s))


    # Processing Plaintext
    P = int.from_bytes(P, "big")
    Psplit = []
    temp = ((P << 1) ^ 1) << (r - 1 - ((P.bit_length()) % r))
    for i in range(int(temp.bit_length() / r)):
        Psplit.insert(0, ((temp >> (i * r)) & 0xFFFFFFFFFFFFFFFF))

    Csplit = []
    for i in range(len(Psplit)-1):
        sr, sc = s_split(s, r)
        sr = sr ^ Psplit[i]
        Csplit.append(sr)
        s = s_merge(sr,sc,r)
        s = perm(s,b)
    sr, sc = s_split(s, r)
    sr = sr ^ Psplit[-1]
    s = s_merge(sr, sc, r)
    Csplit.append(sr >> (sr.bit_length() - (P.bit_length()) % r))

    #Finalisation
    s = perm(s ^ (K << (320-r-k)),a)
    T = (s ^ 0xffffffffffffffffffffffffffffffff) ^ (K ^ 0xffffffffffffffffffffffffffffffff)

    return hex(c_merge(Csplit,r)), hex(T)

key = ascon.get_random_bytes(16)  # zero_bytes(keysize)
key2 = int.from_bytes(key, "big")

nonce = ascon.get_random_bytes(16)  # zero_bytes(16)
nonce2 = int.from_bytes(nonce, "big")


def demo_aead(variant,key,nonce):
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    keysize = 20 if variant == "Ascon-80pq" else 16
    print("=== demo encryption using {variant} ===".format(variant=variant))

    # choose a cryptographically strong random key and a nonce that never repeats for the same key:

    associateddata = b"ASCON"
    plaintext = b"ascon"

    ciphertext = ascon.ascon_encrypt(key, nonce, associateddata, plaintext, variant)
    receivedplaintext = ascon.ascon_decrypt(key, nonce, associateddata, ciphertext, variant)

    if receivedplaintext == None: print("verification failed!")

    ascon.demo_print([("key", key),
                ("nonce", nonce),
                ("plaintext", plaintext),
                ("ass.data", associateddata),
                ("ciphertext", ciphertext[:-16]),
                ("tag", ciphertext[-16:]),
                ("received", receivedplaintext),
                ])
demo_aead("Ascon-128",key = key, nonce = nonce)
print(enc(K = key2, N = nonce2, A = b"ASCON", P = b"ascon"))
#print((enc(K = 0x000102030405060708090A0B0C0D0E0F, N = 0x000102030405060708090A0B0C0D0E0F, A = 0x000102030405060708090A0B0C0D, P = 0x000102030405060708090A0B0C0D0E0F101112131415)))
#print(enc(K = 0x000102030405060708090A0B0C0D0E0F, N = 0x000102030405060708090A0B0C0D0E0F, A = 0x000102030405060708090A0B0C0D0E0F10111213141516, P = None))
