#!/usr/bin/env python
#-*- coding:utf-8 -*-
#author: ev3r

import socket
import thread
import argparse
import re

#  TODO: multithread
#  TODO: record
#  TODO: exception
resultdic = {}

def checkip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):
        return True
    else:
        return False

def parseport(port):
    if port.isdigit() and int(port) > 0 and int(port) < 65535:
        return [int(port)]
    if re.match(r"^(\w+-\w+)$", port):
        lowport = int(port.split('-')[0])
        highport = int(port.split('-')[1])
        if lowport < highport:
            retlist = list(range(lowport,highport))
            retlist.append(highport)
            return retlist
    else:
        return []

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

    #  print args
    if 'filename' in args:
        with open(args.filename, 'r') as f:
            line = f.readline()
            while line:
                ip = line.split(' ')[0]
                port = line.split(' ')[1]
                portlist = parseport(port)
                if checkip(ip) and portlist:
                    resultdic[ip] = []
                    for port in portlist:
                        scan(ip, port)

                    for ip in resultdic:
                        print "Availible ports for " + ip + " are:"
                        for port in resultdic[ip]:
                            print str(port)
                line = f.readline()
        
    else:
        if checkip(args.ip):
            ip = args.ip
            resultdic[ip] = []
            portlist = parseport(args.port)
            if portlist:
                #  print portlist
                for port in portlist:
                    scan(ip, port)

                for ip in resultdic:
                    print "Availible ports for " + ip + " are:"
                    for port in resultdic[ip]:
                        print str(port)
            else:
                print "Wrong Port number!"
        else:
            print "Wrong IP address!"



