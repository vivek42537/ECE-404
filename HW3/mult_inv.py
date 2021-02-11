#!/usr/bin/python3

# HW3
# Vivek Khanolkar
# vkhanolk
# 2/11/2021

#Following code modified from FindMI.py

import sys

if len(sys.argv) != 3:  
    sys.stderr.write("Usage: %s   <integer>   <modulus>\n" % sys.argv[0]) 
    sys.exit(1) 

NUM, MOD = int(sys.argv[1]), int(sys.argv[2])

# utilizing russianPeasant method to bitwise multiply (had to modify slightly 
# since wasn't working with some negative test cases)

def russianPeasant(a, b):
    ans = 0
    if (b < 0) :
        b = -b
        a = -a
    while (b > 0):
        if (b & 1): #if b is odd
            ans = ans + a

        a = a << 1
        b = b >> 1
    
    return ans

def divider(x, y):
    count = 0
    while (x > y):
        x -= y
        count += 1

    return count

def MI(num, mod):
    '''
    This function uses ordinary integer arithmetic implementation of the
    Extended Euclid's Algorithm to find the MI of the first-arg integer
    vis-a-vis the second-arg integer.
    '''
    #print("ANS: ", russianPeasant(-2, -5))
    #print("DIV: ", divider(15, 2))
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = divider(num, mod)
        num, mod = mod, num % mod
        x, x_old = x_old - russianPeasant(q,x), x
        y, y_old = y_old - russianPeasant(q,y), y
        # print("Q: ", q)
        # print("num: ", num)
        # print("mod: ", mod)
        # print("X: ", x, "X_OLD: ", x_old)
        # print("Y: ", y, "Y_OLD: ", y_old)
        # print("________________________________")
    if num != 1:
        print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
    else:
        MI = (x_old + MOD) % MOD
        print("\nMI of %d modulo %d is: %d\n" % (NUM, MOD, MI))

MI(NUM, MOD)

