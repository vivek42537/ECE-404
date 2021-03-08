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
    dbv = ebv.multiplicative_inverse()
        

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
        RSAdecrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

    else :
        print("WRONG INPUT")
