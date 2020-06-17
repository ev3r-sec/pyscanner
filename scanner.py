#!/usr/bin/env python
#-*- coding:utf-8 -*-
#author: ev3r

import socket
import thread
import argparse

resultdic = {}

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
    parser.add_argument('--ip', type=str, dest='ip',
                        help='IP address')
    parser.add_argument('--port', type=int, dest='port',
                        help='Port number')

    args = parser.parse_args()
    resultdic[args.ip] = []
    scan(args.ip, args.port)

    for ip in resultdic:
        print "Availible ports for " + ip + " are:"
        for port in resultdic[ip]:
            print str(port)



