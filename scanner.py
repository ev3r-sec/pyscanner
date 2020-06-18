#!/usr/bin/env python
#-*- coding:utf-8 -*-
#author: ev3r

import socket
import thread
import argparse
import re

resultdic = {}

def checkip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):
        return True
    else:
        return False

def checkport(port):
    if re.match(r"^(\w+|\w+-\w+)$", port):
        return True
    else:
        return False

def scan(ip, port):

    s = socket.socket()
    s.settimeout(0.1)
    if s.connect_ex((ip, port)) == 0:
        resultdic[ip].append(port)
        #  print 'f'
    else:
        #  TODO: record
        pass


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Input the IP address and PORT number.')
    subs = parser.add_subparsers()
    subs.required = True

    file_parser = subs.add_parser('file', help='scan from a file') 
    file_parser.add_argument('filename', type=str,  help='input the filename')
    
    normal_parser = subs.add_parser('ip', help='scan from ip and port number')
    normal_parser.add_argument('ip', type=str, 
                        help='IP address')
    normal_parser.add_argument('port', type=str ,
                        help='Port number')

    args = parser.parse_args()

    if 'filename' in args:
        print "eee"
    else:
        resultdic[args.ip] = []
        scan(args.ip, args.port)

        for ip in resultdic:
            print "Availible ports for " + ip + " are:"
            for port in resultdic[ip]:
                print str(port)



