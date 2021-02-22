#!/usr/bin/python3

# HW4
# Vivek Khanolkar
# vkhanolk
# 2/23/2021

import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')

subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

def genTables(EorD):
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

        return subBytesTable if (EorD == 'E') else invSubBytesTable


def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def get_encryption_key(keyName): #Only takes keysize of 256 bits (32 characters)
    keyFile = open(keyName)
    key = BitVector(textstring = keyFile.read() )
    return key

def subBytes(arr):
    for i in range(4):
        for j in range(4):
            arr[i][j] = BitVector(intVal = subBytesTable[int(arr[i][j])])
    
    return arr

def shiftRowsE(arr):
    for j in range(4):
        arr[1][j] = arr[1][(j+1)%4]
    for j in range(4):
        arr[2][j] = arr[2][(j+2)%4]
    for j in range(4):
        arr[3][j] = arr[3][(j+3)%4] 
    
    return arr

def mixCols(arr):
    mixedState = [[0 for x in range(4)] for x in range(4)]
    hex2 = BitVector(bitstring = '10')
    hex3 = BitVector(bitstring = '11')
    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[0][j], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[1][j], AES_modulus, 8)
        mixedState[0][j] = uno ^ dos ^ arr[2][j] ^ arr[3][j]

    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[1][j], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[2][j], AES_modulus, 8)
        mixedState[0][j] = arr[0][j] ^ uno ^ dos ^ arr[3][j]
    
    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[2][j], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[3][j], AES_modulus, 8)
        mixedState[0][j] = arr[0][j] ^ arr[1][j] ^ uno ^ dos
    
    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[3][j], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[0][j], AES_modulus, 8)
        mixedState[0][j] = dos ^ arr[1][j] ^ arr[2][j] ^ uno

    return mixedState

def encrypt(fileIn, keyName, fileOut):
    key = get_encryption_key(keyName)
    keyWords = gen_key_schedule_256(key)
    bv = BitVector( filename = fileIn ) #BitVector( 'filename.txt' )
    outFile = open(fileOut, 'w')
    subBytes = genTables('E')

    stateArray = [[0 for x in range(4)] for x in range(4)]

    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file( 128 )
        bitvec.pad_from_right(128 - len(bitvec))

        #creating state array
        for i in range(4):
            for j in range(4):
                stateArray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
                
        #xor it with first 4 keywords
        for i in range(4):
            for j in range(4):
                stateArray[i][j] ^= keyWords[i][8*j:(8*(j+1))]

        for x in range(14): #have to do 14 rounds since we have a 256 bit key
            #SubBytes
            stateArray = subBytes(stateArray)
            #ShiftRows
            stateArray = shiftRowsE(stateArray)
            #MixColumns
            if (x != 13):
                stateArray = mixCols(stateArray)
            #Add RoundKey
        
        [LE,RE] = bitvec.divide_into_two() # left and right blocks are swapped to reallign
        bitvec = RE + LE
        myhex = bitvec.get_bitvector_in_hex()
        outFile.write(myhex)
        #myhex.write_to_file(outFile)
    outFile.close()
    print("ENCRYPTED!")

def decrypt(fileIn, keyName, fileOut):
    key = get_encryption_key(keyName)
    round_key = generate_round_keys( key )
    # print("round Key:", round_key)
    with open (fileIn, 'r') as myFile:
        enc = myFile.readlines()
    #print(enc[0])

    bv = BitVector( hexstring = enc[0] ) #bv = BitVector( 'filename.txt' )
    outFile = open(fileOut, 'wb')
    print("LENGTH:", len(bv))
    # while (bv.more_to_read):
    x = 0
    y = 64
    while (y != len(bv) + 64):
        bitvec = bv[x:y]
        for x in reversed(range(16)):
            if bitvec.length() > 0:
                [LE,RE] = bitvec.divide_into_two()  # divide into halves
                newRE = RE.permute(expansion_permutation)  # expansion permutation
                out_xor = newRE ^ round_key[x]  # key mixing
                subsRE = substitute(out_xor)  # S-box substitution
                finalRE = subsRE.permute(p_box_permutation)  # p-box permutation
                bitvec = RE + (LE ^ finalRE) #left becomes right and right becomes left permuted
        
        [LE,RE] = bitvec.divide_into_two()
        bitvec = RE + LE # left and right blocks are swapped to reallign
        bitvec.write_to_file(outFile)
        print(x,y)
        x = y
        y += 64
        
    outFile.close()
    print("DECRYPTED!")

if __name__ == '__main__' :
    if sys.argv[1] == '-e' :
        print("Encrypting...")
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == '-d' :
        print("Decrypting...")
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    else :
        print("WRONG INPUT")