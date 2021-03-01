#!/usr/bin/python3

# HW5
# Vivek Khanolkar
# vkhanolk
# 3/2/2021

import sys
from BitVector import *
import AES2
from AES2 import *

def x931(v0, dt, totalNum ,key_file):
    randos = []
    seed = v0
    for x in range(totalNum):
        dtAES = encrypt(dt, key_file) #encrypt our 'data time' value
        # print("HELLOOOOOOO")
        # print(type(dtAES))
        # print(type(seed))
        dtXOR = dtAES ^ seed #xor with seed value
        rand = encrypt(dtXOR, key_file) #encrypt with XOR val to get our random number
        randos.append(rand)

        randXOR = rand ^ dtAES
        seed = encrypt(randXOR, key_file)

    return randos

if __name__ == "__main__":
    v0 = BitVector(textstring="computersecurity") #v0 will be  128 bits
    #As mentioned before, for testing purposes dt is set to a predetermined value
    dt = BitVector(intVal = 501, size=128)
    listX931 = x931(v0,dt,3,"keyX931.txt")
    #Check if list is correct
    print("{}\n{}\n{}".format(int(listX931[0]),int(listX931[1]),int(listX931[2])))    