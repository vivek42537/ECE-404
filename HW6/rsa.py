#!/usr/bin/python3

# HW6
# Vivek Khanolkar
# vkhanolk
# 3/9/2021

import sys
from BitVector import *
from PrimeGenerator import *

def gcd(a, b):
    while b:                                             
        a,b = b, a%b
    return a

def ppqq(e, flag):
    num = PrimeGenerator(bits = 128)
    p = num.findPrime()
    q = num.findPrime()
    pbv = BitVector(intVal = p, size = 128)
    qbv = BitVector(intVal = q, size = 128)
    tres = BitVector(bitstring= '11')
    if (qbv[0:2] != tres) or (pbv[0:2] != tres): #check leftmost bits of p and q are set
        flag = 0
    if (pbv == qbv): #p and q should not be equal
        flag = 0
    if (gcd(p-1, e) != 1) or (gcd(q-1, e) != 1): #p-1 and q-1 should be coprime
        flag = 0

    if flag == 0:
        flag = 1
        ppqq(e, flag)
    else:
        return p, q

def RSAencrypt(fileIn, fileOut, e, p, q):
    ebv = BitVector(intVal = e)
    nmod = p * q
    totient = (p - 1) * (q - 1)
    dbv = ebv.multiplicative_inverse(BitVector(intVal = totient, size = 256))
    d = int(dbv)

    inbv = BitVector(filename = fileIn)
    outFile = open(fileOut, 'w')

    while(inbv.more_to_read):
        bitvec = inbv.read_bits_from_file(128)
        bitvec.pad_from_right(128 - len(bitvec)) #pad as usual from right
        bitvec.pad_from_left(128) #make it into a 256 block

        enc = pow(int(bitvec), e, nmod)
        encbv = BitVector(intVal = enc, size = 256)
        myhex = encbv.get_bitvector_in_hex()
        outFile.write(myhex)
    
    outFile.close()
    print("ENCRYPTED")

def RSAdecrypt(fileIn, fileOut, e, p, q):
    ebv = BitVector(intVal = e)
    nmod = p * q
    totient = (p - 1) * (q - 1)
    outFile = open(fileOut, 'wb')
    dbv = ebv.multiplicative_inverse(BitVector(intVal = totient, size = 256))
    d = int(dbv)
    
    with open(fileIn, 'r') as myFile:
        enc = myFile.readlines()
    
    bv = BitVector(hexstring = enc[0])
    x = 0
    y = 256

    while(y != len(bv) + 256):
        bitvec = bv[x:y]
        #CRT From lecture notes:
        vp = pow(int(bitvec), d, p)
        vq = pow(int(bitvec), d, q)

        xp = q * int(

if __name__ == '__main__' :
    e = 65537
    if sys.argv[1] == '-g' :
        print("Generating...")
        flag = 1
        p,q = ppqq(e, flag)
        with open(sys.argv[2], 'w') as out1:
            out1.write(str(p))
        with open(sys.argv[3], 'w') as out2:
            out2.write(str(q))
        out1.close()
        out2.close()

    elif sys.argv[1] == '-e' :
        print("Encrypting...")
        pfile = open(sys.argv[3], 'r')
        qfile = open(sys.argv[4], 'r')
        p = int(pfile.read())
        q = int(qfile.read())
        RSAencrypt(sys.argv[2], sys.argv[5], e, p, q)


    elif sys.argv[1] == '-d' :
        print("Decrypting...")
        pfile = open(sys.argv[3], 'r')
        qfile = open(sys.argv[4], 'r')
        p = int(pfile.read())
        q = int(qfile.read())
        RSAdecrypt(sys.argv[2], sys.argv[5], e, p, q)

    else :
        print("WRONG INPUT")
