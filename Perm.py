def split(s): #split s into 5 64 bit blocks
    y = []
    for i in range(5):
        y.insert(0,((s >> (i*64)) & 0xFFFFFFFFFFFFFFFF))
    return y

def merge(s): #merge 5 64 bit blocks into 1
    y=0
    for i in range(5):
        y = y ^ (s[4-i] << (i * 64))
    return y

def addConstant(y, r, power): #power is a or b, y here is a list containing xis
    p12 = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    p8 = [0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    p6 = [0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    if power == 12: cr = p12[r]
    elif power == 8: cr = p8[r]
    else:
        cr = p6[r]
    y[2] = y[2]^cr

    return y

def sub(y):
    sbox = [0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2, 0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c, 0x1e, 0x13, 0x7, 0xe,
            0x0, 0xd, 0x11, 0x18, 0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17]
    x = []

    for i in range(64): #splitting into 5 bit blocks and substituting
        temp = 0b0
        for j in range(5):
            temp ^= (((y[4-j] & (0b1 << i)) >> i) << j) #note, sbox counts from bottom up.
        x.insert(0, temp)
        x[0] = sbox[x[0]]

    for j in range(5): #merging back into 5 64 bit blocks.
        temp = 0b0
        for i in range(64):
            temp ^= (((x[i] & (0b1 << j)) >> j) << (63-i))
        y[4-j] = temp

    return y #return as list of 5 64 bit blocks

def lindiff(y): #y here is a list containing xis
    def circ_shift(s,r):
        temp = 0
        for i in range(r): #create 11111s
            temp += 2**(i)
        return ((s>>r)^((s & temp) << (64-r)))
    temp = y
    y[0] = temp[0] ^ circ_shift(temp[0],19) ^ circ_shift(temp[0],28)
    y[1] = temp[1] ^ circ_shift(temp[1],61) ^ circ_shift(temp[1],39)
    y[2] = temp[2] ^ circ_shift(temp[2],1) ^ circ_shift(temp[2],6)
    y[3] = temp[3] ^ circ_shift(temp[3],10) ^ circ_shift(temp[3],17)
    y[4] = temp[4] ^ circ_shift(temp[4],7) ^ circ_shift(temp[4],41)

    return y

def perm(s,power): #s is data, a/b is power i.e number of rounds
    s = split(s)

    for i in range(power):
        s = addConstant(s, i, power)
        s = sub(s)
        s = lindiff(s)

    return merge(s)


#print(sub(split(0x00000000000000000000000000000000000000000000000000000000000000000000000000000000)))
#print(hex(perm(0x00000000000000000000000000000000000000000000000000000000000000000000000000000000,12)))
#print(hex(merge(split(0xFFFFFFFFFFFFFFFF1111111111111111222222222222222233333333333333334444444444444444))))
#print(lindiff(split(0xFFFFFFFFFFFFFFFF1111111111111111222222222222222233333333333333334444444444444444)))
#print(hex(merge(sub(split(0xFFFFFFFFFFFFFFFF1111111111111111222222222222222233333333333333334444444444444444)))))