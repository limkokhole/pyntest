#!/bin/bash
# Pyntest (https://www.github.com/R3nt0n/pyntest)
# R3nt0n (https://www.github.com/R3nt0n)

apt update -y && apt upgrade -y

apt install python-pip -y
apt install whois -y
apt install nmap -y
apt install python-dnspython -y

pip install dnspython==1.15.0
pip install netaddr==0.7.19
pip install python-nmap==0.6.1
