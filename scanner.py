#!/usr/bin/env python
#-*- coding:utf-8 -*-
#author: ev3r

import socket
import thread
import argparse
import re
import threading

#  TODO: output
#  TODO: record
#  TODO: exception

#  store the result
resultdic = {}

#  port number for each thread
portnumeachthread = 20

#  thread list
threads = []

lock = threading.Lock()

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

def portscanner(addrtuplelist):
    global resultdic
    for addr in addrtuplelist:
        s = socket.socket()
        s.settimeout(0.1)
        if s.connect_ex(addr) == 0:
            lock.acquire()
            resultdic[addr[0]].append(addr[1])
            lock.release()
            #  print 'f'
        else:
            #  TODO: record
            pass

def multhreadassign(addrtuplelist):
    tuplelength = len(addrtuplelist)
    threadnum = tuplelength / portnumeachthread 
    if threadnum == 0:
        for addr in addrtuplelist:
            portscanner(addr)
    else:
        for i in range(0, threadnum):
            startnum = i * portnumeachthread
            if startnum+20 <= tuplelength:
                subtuplelist = addrtuplelist[startnum:startnum+20]
                t = threading.Thread(target=portscanner, args=(subtuplelist,))
                threads.append(t)
                t.start()
            else:
                subtuplelist = addrtuplelist[startnum:tuplelength-1]
                t = threading.Thread(target=portscanner, args=(addrtuplelist,))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Input the IP address and PORT number.')
    subs = parser.add_subparsers()
    subs.required = True

    file_parser = subs.add_parser('file', help='scan from a file') 
    file_parser.add_argument('filename', type=str,  help='input the filename')
    
    normal_parser = subs.add_parser('ip', help='scan from ip and port number')
    normal_parser.add_argument('ip', type=str, help='IP address')
    normal_parser.add_argument('port', type=str, help='Port number')

    args = parser.parse_args()

    #  print args
    if 'filename' in args:
        with open(args.filename, 'r') as f:
            addrtuplelist = []
            line = f.readline()
            while line:
                ip = line.split(' ')[0] # TODO: other splitter
                port = line.split(' ')[1]
                portlist = parseport(port)
                if checkip(ip) and portlist:
                    if ip not in resultdic.keys():
                        resultdic[ip] = []
                    for port in portlist: # TODO: faster 
                        if (ip, port) not in addrtuplelist:
                            addrtuplelist.append((ip, port))

                    #  for ip in resultdic:
                        #  print "Availible ports for " + ip + " are:"
                        #  for port in resultdic[ip]:
                            #  print str(port)
                line = f.readline()
            #  print addrtuplelist
            multhreadassign(addrtuplelist)
        
    else:
        if checkip(args.ip):
            ip = args.ip
            resultdic[ip] = []
            portlist = parseport(args.port)
            if portlist:
                addrtuplelist = []
                #  print portlist
                for port in portlist:
                    addrtuplelist.append((ip, port))
                multhreadassign(addrtuplelist)

            else:
                print "Wrong Port number!"
        else:
            print "Wrong IP address!"


    for ip in resultdic:
        print "Availible ports for " + ip + " are:"
        for port in resultdic[ip]:
            print str(port)

