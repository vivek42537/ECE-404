#!/usr/bin/python3

# HW5
# Vivek Khanolkar
# vkhanolk
# 3/2/2021

import sys
from BitVector import *

import os

#Note: https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf was used to visualize steps
#following code taken and modified from professor Avi Kak's Lecture 8 notes (gen_key_schedule.py and gen_tables.py)
AES_modulus = BitVector(bitstring='100011011')

subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

def genKeys(key_bv):
    key_words = []
    keysize = 256
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []
    # print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        # if word_index % 4 == 0: print("\n")
        # print("word %d:  %s" % (word_index, str(keyword_in_ints)))
        key_schedule.append(keyword_in_ints)
    num_rounds = None
    if keysize == 256: num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                                       key_words[i*4+3]).get_bitvector_in_hex()
    # print("\n\nRound keys in hex (first key for input block):\n")
    # for round_key in round_keys:
    #     print(round_key)
    return round_keys

def genTables():
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

def substituteBytes(arr):
    for i in range(4):
        for j in range(4):
            #print(subBytesTable[i*j])
            arr[i][j] = BitVector(intVal = subBytesTable[int(arr[i][j])], size=8)
    return arr

#had to follow lecture notes sideways since created state array with bits going horizontally instead of vertically
def shiftRowsE(arr): #Note: necessary to do with new matrix, if manipulate arr shifts get overwritten
    shiftedState = [[None for x in range(4)] for x in range(4)]
    for j in range(4):
        shiftedState[j][0] = arr[j][0]
    for j in range(4):
        shiftedState[j][1] = arr[(j+1)%4][1]
    for j in range(4):
        shiftedState[j][2] = arr[(j+2)%4][2]
    for j in range(4):
        shiftedState[j][3] = arr[(j+3)%4][3]
    
    return shiftedState
#based on lecture 8 notes:
def mixCols(arr):
    mixedState = [[None for x in range(4)] for x in range(4)]
    hex2 = BitVector(bitstring = '10')
    hex3 = BitVector(bitstring = '11')
    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[j][0], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[j][1], AES_modulus, 8)
        mixedState[j][0] = uno ^ dos ^ arr[j][2] ^ arr[j][3]

    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[j][1], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[j][2], AES_modulus, 8)
        mixedState[j][1] = arr[j][0] ^ uno ^ dos ^ arr[j][3]
    
    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[j][2], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[j][3], AES_modulus, 8)
        mixedState[j][2] = arr[j][0] ^ arr[j][1] ^ uno ^ dos
    
    for j in range(4):
        uno = hex2.gf_multiply_modular(arr[j][3], AES_modulus, 8)
        dos = hex3.gf_multiply_modular(arr[j][0], AES_modulus, 8)
        mixedState[j][3] = dos ^ arr[j][1] ^ arr[j][2] ^ uno

    return mixedState
#xor each round key after each round
def addRoundKey(arr, keyWords, round):
    for i in range(4):
        for j in range(4):
            arr[i][j] ^= keyWords[(4 * round) + 4 + i][8*j:8*(j+1)] #need to start from second keyWord till end
    
    return arr


def encrypt(inputBV, keyName):
    # key = get_encryption_key(keyName)
    # roundKey = genKeys(key)
    # keyWords = gen_key_schedule_256(key)
    bitvec = inputBV
    keyWords = keyName
    # genTables()

    # if len(bitvec) != 128:
    #     bitvec.pad_from_right(128 - len(bitvec))

    stateArray = [[0 for x in range(4)] for x in range(4)]

    #create state array
    for i in range(4):
        for j in range(4):
            stateArray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
            
    #xor it with first 4 keywords
    for i in range(4):
        for j in range(4):
            stateArray[i][j] ^= keyWords[i][8*j:(8*(j+1))]

    for x in range(14): #have to do 14 rounds since we have a 256 bit key
        #SubBytes
        stateArray = substituteBytes(stateArray)

        #ShiftRows
        stateArray = shiftRowsE(stateArray)

        #MixColumns
        if (x != 13):
            stateArray = mixCols(stateArray)

        #Add RoundKey
        stateArray = addRoundKey(stateArray, keyWords, x)

    stateBV = BitVector(size = 0)
    for i in range(4):
        for j in range(4):
            stateBV += stateArray[i][j]

    return stateBV
    print("ENCRYPTED!")


def ctr_aes_image(iv, image_file = 'image.ppm', out_file = 'enc_image.ppm', key_file = 'key.txt'):
    outFile = open(out_file, 'wb')

    with open(image_file, 'rb') as myFile:
        head = [next(myFile) for x in range(3)]
    
    for x in range(3):
        outFile.write(head[x])
    
    key = get_encryption_key(key_file)
    keyWords = gen_key_schedule_256(key)
    genTables()

    imageBV = BitVector(filename = image_file)

    while (imageBV.more_to_read):
        bitvec = imageBV.read_bits_from_file( 128 )
        # bitvec.pad_from_right(128 - (len(bitvec) % 128)) #gives size of 47486
        bitvec.pad_from_right(128 - len(bitvec))

        # print("BVLEN:", len(bitvec))

        blkEnc = encrypt(iv, keyWords)
        xblk = bitvec ^ blkEnc
        xblk.write_to_file(outFile)

        ivInt  = int(iv) + 1
        iv = BitVector(intVal = ivInt, size = 128)

        # print("LENIV:", len(iv))
        # iv = BitVector(intVal = (iv.int_val() + 1), size = 128)
        x += 1
        
    outFile.close()


if __name__ == '__main__' :
    file1 = os.path.getsize('enc_image_sample.ppm')
    file2 = os.path.getsize('enc_image.ppm')
    file3 = os.path.getsize('image.ppm')
    print("SAMPLE:", file1)
    print("MINE:", file2)
    print("ORIGIN:", file3)
    # iv = BitVector(textstring="computersecurity") #iv will be  128 bits, usually we use random number from x931 initialized as a vector
    # print("LENIV:", len(iv))
    # ctr_aes_image(iv, 'image.ppm', 'enc_image.ppm', 'keyCTR.txt')