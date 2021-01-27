# HW1
# Vivek Khanolkar
# vkhanolk
# 1/28/2021
#!/usr/bin/python3

import sys
#had to add this line so I can access BitVector since it got downloaded to another directory
#sys.path.insert(0, '/home/shay/a/vkhanolk/.local/lib/python3.6/site-packages')

#The following code is taken (and slightly modified) from Lecture 2
from BitVector import *                                                     #(A)

if len(sys.argv) is not 3:                                                  #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted file and the other for the '''
             '''decrypted output file''')

PassPhrase = "Hopes and dreams of a million years"                          #(C)

BLOCKSIZE = 16                                                              #(D)
numbytes = BLOCKSIZE // 8                                                   #(E)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  #(F)
for i in range(0,len(PassPhrase) // numbytes):                              #(G)
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         #(H)
    bv_iv ^= BitVector( textstring = textstr )                              #(I)

# Create a bitvector from the ciphertext hex string:
FILEIN = open(sys.argv[1])                                                  #(J)
encrypted_bv = BitVector( hexstring = FILEIN.read() )                       #(K)

#Now need to try 0 - 2^16 keys until file is decrypted
print("HELLOA")

#def bruteForce() :
for xk in range(2**16 + 1):
    key_bv = BitVector(intVal = xk, size = 16) #taken from BitVector documentation (C3)
    if xk % 10000 == 0:
        print("Current num:", xk)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )                                    #(T)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv                                            #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          #(W)
        temp = bv.deep_copy()                                                   #(X)
        bv ^=  previous_decrypted_block                                         #(Y)
        previous_decrypted_block = temp                                         #(Z)
        bv ^=  key_bv                                                           #(a)
        msg_decrypted_bv += bv                                                  #(b)

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     #(c)
    if "Yogi Berra" in outputtext:
        print("DECODED!")
        print("KEY:", xk)
        # Write plaintext to the output file:
        FILEOUT = open(sys.argv[2], 'w')                                            #(d)
        FILEOUT.write(outputtext)                                                   #(e)
        FILEOUT.close()                                                             #(f)
        exit()

# if __name__ == '__main__' :
#     bruteForce
