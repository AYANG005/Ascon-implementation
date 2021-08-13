from Perm import perm
import ascon
import math

def s_split(s,r): #splits state S in sr and sc
    sr = (s >> (320 - r))
    temp = 0
    for i in range(320-r):  # create 11111s
        temp += 2 ** (i)
    sc = s & temp
    return sr, sc

def s_merge(sr,sc,r):#merges sr and sc into s
    s = (sr << (320-r)) ^ sc
    return s

def c_merge(c,r): #merges everything but the last ciphertext block, used for plaintext in decryption too
    y = 0
    for i in range(len(c)-1):
        y = y ^ (c[len(c) - i - 2] << (i * r))
    return y

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

def get_random_bytes(num):
    import os
    return bytes(bytearray(os.urandom(num)))

def enc(K,N,A,P):

    #Initialisation
    K = int.from_bytes(K, "big")
    N = int.from_bytes(N, "big")
    iv = 0x80400c0600000000
    a = 0x0c
    b = 0x06
    r = 0x40
    k = 0x80
    s = (((iv << k) ^ K) << 128) ^ N  #K.bit_length()) ^ K #had set size to 128 based off test code.
    s = (perm(s, a) ^ ((0 << 320) ^ K))

    #Processing Associated data
    Asplit = []
    if A != 0 and A!=b'':
        count = 0 #computing number of 0s to append
        temp = len(A)*8
        while temp > 0:
            temp-=r
            count+=1
        number_of_zeros = r*count - len(A)*8
        if number_of_zeros != 0: number_of_zeros -= 1
        else: number_of_zeros = 63

        A = int.from_bytes(A, "big")
        temp = ((A << 1) ^ 1) << (number_of_zeros) #note that 0s in front of bit string are not to be removed

        for i in range(math.ceil(temp.bit_length()/r)): #splitting A padded into blocks
            Asplit.insert(0, ((temp >> (i * r)) & 0xFFFFFFFFFFFFFFFF))

        for i in range(len(Asplit)):
            sr,sc = s_split(s,r)
            s = perm(((sr^Asplit[i])<<(320-r))^sc,b)
    s = s ^ 1
    # Processing Plaintext
    count = 0  # computing number of 0s to append
    plaintextlen = len(P)
    temp = len(P) * 8
    while temp > 0:
        temp -= r
        count += 1
    number_of_zeros = r * count - len(P) * 8
    if P == b'': number_of_zeros = 63
    elif number_of_zeros != 0:
        number_of_zeros -= 1  # if length isnt a mult of 64, -1 for the extra 1 to append
    else:
        number_of_zeros = 63  # if its a mult of 64
    P = int.from_bytes(P, "big")
    Psplit = []
    temp = ((P << 1) ^ 1) << (number_of_zeros)  # padded P
    for i in range(math.ceil(temp.bit_length() / r)):
        Psplit.insert(0, ((temp >> (i * r)) & 0xFFFFFFFFFFFFFFFF))
    Csplit = []
    for i in range(len(Psplit) - 1):  # preparing all but last ciphertext, algo
        sr, sc = s_split(s, r)
        sr = sr ^ Psplit[i]
        Csplit.append(sr)
        s = s_merge(sr, sc, r)
        s = perm(s, b)
    sr, sc = s_split(s, r)
    sr = sr ^ Psplit[-1]  # the last Ci
    s = s_merge(sr, sc, r)
    Csplit.append(sr >> (number_of_zeros + 1))
    ciphertext = (c_merge(Csplit, r) << (r - number_of_zeros - 1)) ^ Csplit[-1]


    #Finalisation
    s = perm(s ^ (K << (320-r-k)),a)
    temp = 0
    for i in range(128):  # create 11111s to take ceiling
        temp += 2 ** (i)
    T = (s & temp) ^ (K & temp)
    print("Ciphertext: " + hex(ciphertext), "Tag:" + hex(T))
    if len(int_to_bytes(ciphertext))!=plaintextlen: cipher = (plaintextlen - len(int_to_bytes(ciphertext)))*b'\00' + int_to_bytes(ciphertext) #adding 0s in front to match byte format
    else: cipher =  int_to_bytes(ciphertext)
    return [cipher, int_to_bytes(T)]



def dec(K,N,A,C,T):

    #Initialisation
    K = int.from_bytes(K, "big")
    N = int.from_bytes(N, "big")
    iv = 0x80400c0600000000
    a = 0x0c
    b = 0x06
    r = 0x40
    k = 0x80
    s = (((iv << k) ^ K) << 128) ^ N  #K.bit_length()) ^ K #had set size to 128 based off test code.
    s = (perm(s, a) ^ ((0 << 320) ^ K))

    #Processing Associated data
    Asplit = []
    if A != 0 and A!=b'':
        count = 0 #computing number of 0s to append
        temp = len(A)*8
        while temp > 0:
            temp-=r
            count+=1
        number_of_zeros = r*count - len(A)*8
        if number_of_zeros != 0:number_of_zeros -= 1 #if len A isnt a mult of 64
        else:number_of_zeros = 63 #if len A is a mult of 64

        A = int.from_bytes(A, "big")
        temp = ((A << 1) ^ 1) << (number_of_zeros) #note that 0s in front of bit string are not to be removed
        for i in range(math.ceil(temp.bit_length()/r)): #splitting A padded into blocks, +1 is to take up
            Asplit.insert(0, ((temp >> (i * r)) & 0xFFFFFFFFFFFFFFFF))

        for i in range(len(Asplit)):
            sr,sc = s_split(s,r)
            s = perm(((sr^Asplit[i])<<(320-r))^sc,b)
    s = s ^ 1

    # Processing Ciphertext
    cipherlen = len(C)
    lastlen = (len(C) * 8)%64 #last ciphertext block length
    if (int.from_bytes(C, "big") == 0) and (C!=b''): lastlen = 8 #for when its b'\x00' instead of b''
    temp = 0
    for i in range(lastlen):  # create 11111s
        temp += 2 ** (i)
    C = int.from_bytes(C, "big")
    Csplit = []
    Csplit.insert(0,C & temp) #insert last block
    temp = C >> lastlen #removing last block to split the rest
    for i in range(math.ceil(temp.bit_length() / r)): #splitting into 64 bit blocks
        Csplit.insert(0, ((temp >> (i * r)) & 0xFFFFFFFFFFFFFFFF))
    Psplit = []
    for i in range(len(Csplit)-1): #applying algo to everything but last plaintext
        sr, sc = s_split(s, r)
        pi = sr ^ Csplit[i]
        Psplit.append(pi)
        s = s_merge(Csplit[i],sc,r)
        s = perm(s,b)
    sr, sc = s_split(s, r)

    pi = (sr>>(r-lastlen)) ^ Csplit[-1] #applying algo to last plaintext block
    Psplit.append(pi)
    sr = sr ^ (((pi << 1) ^ 1) << (64-1-lastlen))
    s = s_merge(sr,sc,r)
    plaintext = (c_merge(Psplit, r) << (lastlen)) ^ Psplit[-1] #combining Psplit list to plaintext integer
    #Finalisation
    s = perm(s ^ (K << (320-r-k)),a)
    temp = 0
    for i in range(128):  # create 11111s
        temp += 2 ** (i)
    T_new = (s & temp) ^ (K & temp)
    if T_new == int_from_bytes(T):
        print("Plaintext: "+hex(plaintext))
        if len(int_to_bytes(plaintext)) != cipherlen: #adding 0s in front to match byte format
            plaintext = (cipherlen - len(int_to_bytes(plaintext))) * b'\00' + int_to_bytes(plaintext)
        else:
            plaintext = int_to_bytes(plaintext)
        return plaintext
    else:
        print("Different Tag")
        return None

def demo_aead(variant,key,nonce, assoc, plain):
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    keysize = 20 if variant == "Ascon-80pq" else 16
    print("=== demo encryption using {variant} ===".format(variant=variant))

    # choose a cryptographically strong random key and a nonce that never repeats for the same key:

    associateddata = assoc
    plaintext = plain

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
    return ciphertext[:-16], ciphertext[-16:]


to_break = 0
for i in range(1000):
    for j in range(10000):
        key = get_random_bytes(16)  # zero_bytes(keysize)

        nonce = get_random_bytes(16)  # zero_bytes(16)

        assoc = get_random_bytes(i)  # b"ASCONASCONASCONASCONASCONASCON"

        plain = get_random_bytes(i)  # b"asconasconasconasconasconasconasconascon"

        corr_c, corr_t = demo_aead("Ascon-128", key=key, nonce=nonce, assoc=assoc, plain=plain)
        c, t = enc(K=key, N=nonce, A=assoc, P=plain)
        p = dec(K=key, N=nonce, A=assoc, C=c, T=t)
        # print(hex(int_from_bytes(ascon.ascon_decrypt(key = key, nonce = nonce, associateddata = assoc, ciphertext = c+t, variant="Ascon-128"))))
        if (corr_c != c) or (plain != p) or (int_from_bytes(corr_t) != int_from_bytes(t)):
            print("Error")
            print(p)
            print(c)
            print("key", key)
            print("nonce", nonce)
            print("assoc",assoc)
            print("plain",plain)
            print("Causes: ")
            print(corr_c != c)
            print(corr_c,c)
            print(plain != p)
            print(plain,p)
            print(corr_t != t)
            print(corr_t,t)
            to_break = True
            break
    if to_break == True: break
"""
"""
"""
key = b'\xb5\xa9\xc0\xf5\xe3\x1a\xab{1\x8fOu\x148\xa7\x0f'  # zero_bytes(keysize)
nonce = b'\xbd\\Uv?\x10\x91(\x00\xc9\x13UK\xb2\xf0\xd0'    # zero_bytes(16)
assoc = b'.'   # b"ASCONASCONASCONASCONASCONASCON"
plain = b'\xe1'    # b"asconasconasconasconasconasconasconascon"

corr_c, corr_t = demo_aead("Ascon-128", key=key, nonce=nonce, assoc=assoc, plain=plain)
c, t = enc(K=key, N=nonce, A=assoc, P=plain)
p = dec(K=key, N=nonce, A=assoc, C=c, T=t)

key = b":U\xb4'\xf2\x1cr\xfb\xb3\x87G\xf4\xc7.\x85\x08"  # zero_bytes(keysize)
nonce = b'\x1a\xa53\xa1R/2u\xf8f\xcd|\xb3\xd7\xd5\xfe'   # zero_bytes(16)
assoc = b''   # b"ASCONASCONASCONASCONASCONASCON"
plain = b''   # b"asconasconasconasconasconasconasconascon"

corr_c, corr_t = demo_aead("Ascon-128", key=key, nonce=nonce, assoc=assoc, plain=plain)
c, t = enc(K=key, N=nonce, A=assoc, P=plain)
p = dec(K=key, N=nonce, A=assoc, C=c, T=t)

if (corr_c != c) or (plain != p) or (int_from_bytes(corr_t) != int_from_bytes(t)):
            print("Error")
            print(p)
            print(c)
            print("key", key)
            print("nonce", nonce)
            print("assoc",assoc)
            print("plain",plain)
            print("Causes: ")
            print(corr_c != c)
            print(corr_c,c)
            print(plain != p)
            print(plain,p)
            print(corr_t != t)
            print(corr_t,t)
"""