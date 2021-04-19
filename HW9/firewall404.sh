#!/bin/sh

#HW9
#Vivek Khanolkar
#vkhanolk
#4/6/2021

#Question 1: remove any previous rules or chains
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t nat -F
sudo iptables -t nat -X
#flushes out filter, and nat

#Question 2: for outgoing packets change soure IP to my IP address
sudo iptables -t nat -A POSTROUTING -p tcp -o wlan0 -j MASQUERADE

#Question 3: block all new packets from yahoo.com
sudo iptables -A INPUT -p tcp -s yahoo.com -j DROP

#Question 4: block computer from being pinged
#used code from : https://serverfault.com/questions/209140/iptables-how-to-drop-incoming-pings-from-host-but-allow-ping-responses
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

#Question 5: set up port-forwarding
sudo iptables -t nat -A PREROUTING -p tcp --dport 49999 -j REDIRECT --to-port 22
#Question 6: allow SSH to access my machine
sudo iptables -A INPUT -s 128.46.4.61 -p tcp --destination-port 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --destination-port 22 -j DROP

#Question 7: limit connection requests to 30/min after 60 connections (prevent DoS attacks)

sudo iptables -A FORWARD -p tcp --syn -m limit --limit 30/m --limit-burst 60 -j ACCEPT

#Question 8: drop any other packets
sudo iptables -A INPUT -p all -j REJECT --reject-with icmp-host-prohibited

#test rules with: sudo iptables -L

