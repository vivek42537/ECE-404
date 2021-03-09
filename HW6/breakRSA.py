#!/usr/bin/python3

# HW6
# Vivek Khanolkar
# vkhanolk
# 3/9/2021

import sys
from BitVector import *
from rsa import *
from solve_pRoot_BST import * #Prof. Avi Kak lecture 12 file imported
from PrimeGenerator import * #Prof. Avi Kak lecture 12 file imported

def crackRSA(fileIn, fileOut, e, nlist):
    outFile = open(fileOut, 'wb')
    N = nlist[0] * nlist[1] * nlist[2]
    Nbv = [BitVector(intVal = i) for i in nlist]
    #need to get the 'inverses of our three n keys
    Nrevised = [N/x for x in nlist]
    NrevInt = list(map(int, Nrevised))
    NrevBV = [BitVector(intVal = int(i)) for i in Nrevised]

    Dlist = [] * 3
    for y in range(3):
        Dlist.append(int(NrevBV[y].multiplicative_inverse(Nbv[y])))

    
    Ctotal = [] * 3


    inBV = [BitVector(filename = x) for x in fileIn]
    # print("CHEERIO")
    # for x in inBV:
    #     print(x)
    with open(fileIn)

    x = 0
    y = 256
    print("HEREEEEE")
    print(len(fileIn[0]) + 256)
    while(y != len(fileIn[0]) + 256):
        Ctotal.clear()
        for i in inBV:
            Ctotal.append(int(i[x:y]))
        
        m3list = [Ctotal[i] * Nrevised[i] * Dlist[i] for i in range(3)]
        m = sum(m3list)
        cubic = solve_pRoot(3, m)
        final = BitVector(intVal = cubic, size = 128)
        final.write_to_file(outFile)
        # print(x, y)
        x = y
        y += 256
    # while (inBV[0].more_to_read):
    #     Ctotal.clear()
    #     for x in range(3):
    #         Ctotal.append(int(inBV[x].read_bits_from_file(256)))
        
    #     # crt = Ctotal * NrevInt * Dlist
    #     crtlist = [Ctotal[i] * Nrevised[i] * Dlist[i] for i in range(3)]
    #     crt = sum(crtlist)
    #     cubic = solve_pRoot(3, crt)
    #     let = BitVector(intVal = cubic, size = 256)
    #     outFile.write(let.get_bitvector_in_ascii())

    outFile.close()

if __name__ == '__main__' :
    e = 3
    if sys.argv[1] == '-e' :
        print("Generating...")
        flag = 1
        plist, qlist = map(list, zip(*[ppqq(e, flag) for i in range(3)]))
        nlist = [a * b for a, b in zip(plist, qlist)] #these are our 3 public keys
        
        with open(sys.argv[6], 'w') as out1:
            for x in nlist:
                out1.write(str(x) + '\n')
        out1.close()
        print("Encrypting...")

        ENC123 = [sys.argv[3], sys.argv[4], sys.argv[5]]

        for x in range(3):
            RSAencrypt(sys.argv[2], ENC123[x], e, plist[x], qlist[x])

    elif sys.argv[1] == '-c' :
        print("Cracking...")
        with open(sys.argv[5], 'r') as pubKeys:
            y = pubKeys.readlines()
        
        nlist = [x.strip() for x in y]
        nlist = list(map(int, nlist))
        ENC123 = [sys.argv[2], sys.argv[3], sys.argv[4]]

        crackRSA(ENC123, sys.argv[6], e, nlist)

    else :
        print("WRONG INPUT")
