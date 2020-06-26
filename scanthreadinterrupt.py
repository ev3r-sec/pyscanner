#!/usr/bin/env python
#-*- coding:utf-8 -*-
#author: ev3r

import socket
import thread
import argparse
import re
import threading
import os
import sys
import json
import base64
import yaml

#  TODO: exception

#  store the result
resultdic = {}

#  port number for each thread
portnumeachthread = 200

#  thread list
threads = []

lock = threading.Lock()

timeout = 0.5

#  check interrupt
is_exit = False

exittuplelist = []

def checkip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):
        return True
    else:
        return False

def parseport(port):
    if port.isdigit() and int(port) > 0 and int(port) < 65536:
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
    global resultdic
    s = socket.socket()
    s.settimeout(timeout)
    if s.connect_ex((ip, port)) == 0:
        if ip not in resultdic.keys():
            resultdic[ip] = []
        resultdic[ip].append(port)
    else:
        pass

def portscanner(addrtuplelist):
    global resultdic
    global is_exit
    global exittuplelist
    record = 0
    length = len(addrtuplelist)
    for i in range(length):
        addr = addrtuplelist[i]
        if is_exit:
            break
        if isinstance(addr, list):
            addr = (addr[0], addr[1])
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex(addr) == 0:
                lock.acquire()
                if addr[0] not in resultdic.keys():
                    resultdic[addr[0]] = []
                resultdic[addr[0]].append(addr[1])
                lock.release()
            else:
                pass
        except:
            print 'still error'
            pass

    if is_exit:
        lock.acquire()
        exittuplelist = exittuplelist + addrtuplelist[record:length]
        lock.release()


def multhreadassign(addrtuplelist):
    global is_exit
    global portnumeachthread
    print '-'*60
    print "Starting pyscanner...."
    print '-'*60
    tuplelength = len(addrtuplelist)
    threadnum = tuplelength / portnumeachthread 
    try:
        if threadnum == 0:
            for addr in addrtuplelist:
                scan(addr[0], addr[1])
        else:
            for i in range(0, threadnum):
                startnum = i * portnumeachthread
                if startnum+portnumeachthread <= tuplelength:
                    subtuplelist = addrtuplelist[startnum:startnum+portnumeachthread]
                    t = threading.Thread(target=portscanner, args=(subtuplelist,))
                    t.setDaemon(True)
                    threads.append(t)
                    t.start()
                else:
                    subtuplelist = addrtuplelist[startnum:tuplelength-1]
                    t = threading.Thread(target=portscanner, args=(addrtuplelist,))
                    t.setDaemon(True)
                    threads.append(t)
                    t.start()

            for t in threads:
                t.join()

    except KeyboardInterrupt:
        print "detected KeyboardInterrupt"
        is_exit = True
        alive = True
        while alive:
            detected = False
            for t in threads:
                if t.isAlive():
                    detected = True
            alive = detected
            


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Input the IP address and PORT number.')
    subs = parser.add_subparsers()
    subs.required = True

    file_parser = subs.add_parser('file', help='scan from a file') 
    file_parser.add_argument('filename', type=str,  help='input the filename')
    
    normal_parser = subs.add_parser('ip', help='scan from ip and port number')
    normal_parser.add_argument('ip', type=str, help='IP address')
    normal_parser.add_argument('port', type=str, help='Port number')

    interrupt_parser = subs.add_parser('continue', help='continue last scan')
    interrupt_parser.add_argument('intfile', type=str, help='input the file log')
    args = parser.parse_args()

    if 'filename' in args:
        try:
            with open(args.filename, 'r') as f:
                addrtuplelist = []
                line = f.readline()
                while line:
                    ip = line.split(' ')[0] # TODO: other splitter
                    port = line.split(' ')[1]
                    portlist = parseport(port)
                    if checkip(ip) and portlist:
                        for port in portlist: # TODO: faster 
                            if (ip, port) not in addrtuplelist:
                                addrtuplelist.append((ip, port))

                    line = f.readline()
                multhreadassign(addrtuplelist)
        except KeyboardInterrupt:
            print "exiting"
            sys.exit()
        except:
            print "File error! Please check again!"
            sys.exit()
        
    elif 'ip' in args:
        if checkip(args.ip):
            ip = args.ip
            resultdic[ip] = []
            portlist = parseport(args.port)
            if portlist:
                addrtuplelist = []
                for port in portlist:
                    addrtuplelist.append((ip, port))
                multhreadassign(addrtuplelist)

            else:
                print "Wrong Port number!"
                sys.exit()
        else:
            print "Wrong IP address!"
            sys.exit()

    else:
        try:
            with open(args.intfile, 'rb') as f:
                resultdic = yaml.safe_load(f.readline())
                addrtuplelist = yaml.safe_load(f.readline())
                print resultdic
                multhreadassign(addrtuplelist)
        except KeyboardInterrupt:
            print "exiting"
            sys.exit()
        except:
            print "File error! Please check again!"
            sys.exit()



    if is_exit:
        resultjson = json.dumps(resultdic, ensure_ascii=False)
        exitlist = json.dumps(exittuplelist, ensure_ascii=False)
        f = open('interrupt.txt', 'wb')
        f.write(resultjson + '\n' + exitlist)
        f.close()
        sys.exit()
    for ip in resultdic:
        print '-'*60
        print "Availible ports for " + ip + " are:"
        print '-'*60
        for port in resultdic[ip]:
            print str(port)

