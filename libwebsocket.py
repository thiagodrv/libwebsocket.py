#Copyright (c) 2011 Thiago Varela

#This software is licensed under the terms of the MIT License:

#Permission is hereby granted, free of charge, to any person obtaining
#a copy of this software and associated documentation files
#(the "Software"), to deal in the Software without restriction,
#including without limitation the rights to use, copy, modify, merge,
#publish, distribute, sublicense, and/or sell copies of the Software,
#and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be
#included in all copies or substantial portions of the Software.

#Version 0.0.1 alpha

from urlparse import urlparse
import sys
import socket
import thread
import random
import md5
import time

class WebsocketCommon:
    """This class implements the websocket methods used by both the server and
    the client classes"""
    readyState = 0
    conn = None
    onmessage = None
    onerror = None
    onopen = None
    onclose = None
    def send(self, data):
        if self.readyState == 1:
            self.conn.sendall(self._frame(data))
            return True
        else:
            print 'error - not connected'
            return False

    def close(self):
        self.readyStatus = 2 #closing
        self._closehandshake()
        self._conn_close()
        time.sleep(1) #we have to give the receiver thread time to close itself
        return

    def _frame(self, data):
        framed_data = chr(0x00)+data+chr(0xFF)
        return framed_data

    def _unframe(self, data):
        if data[0] != chr(0x00) or data[len(data)-1] != chr(0xFF): #check framing
            #raise error - incorrect framing
            print 'error - incorrect framing' 
            return ''
        else:
            unframed = data[1:len(data)-1]
            return (unframed)

    def _closehandshake(self):
        data = chr(0xFF)+chr(0x00)
        self.conn.sendall(data)

    class bf(object):
        #Copyright 2002 Sebastien Keim
        #http://code.activestate.com/recipes/113799-bit-field-manipulation
        #Licensed under the PSF License
        #http://www.opensource.org/licenses/PythonSoftFoundation
        def __init__(self,value=0):
            self._d = value
        def __getitem__(self, index):
            return (self._d >> index) & 1 
        def __setitem__(self,index,value):
            value    = (value&1L)<<index
            mask     = (1L)<<index
            self._d  = (self._d & ~mask) | value
        def __getslice__(self, start, end):
            mask = 2L**(end - start) -1
            return (self._d >> start) & mask
        def __setslice__(self, start, end, value):
            mask = 2L**(end - start) -1
            value = (value & mask) << start
            mask = mask << start
            self._d = (self._d & ~mask) | value
            return (self._d >> start) & mask
        def __int__(self):
            return self._d

    def _bitfield(self, number):
        b = self.bf(number)
        return chr(b[0:8])+chr(b[8:16])+chr(b[16:24])+chr(b[24:32])

    def _conn_close(self):
        self.readyState = 3
        self.conn.close()
        if self.onclose:
            self.onclose()

    def _receiver(self, name, conn):
        conn_f = self.conn.makefile()
        received = ''
        complete_frame = False
        while self.readyState == 1:
            while not complete_frame: #read data until we have an end
                try:                  #frame delimiter
                    received += self.conn.recv(4096)
                except:
                    #connection has been closed by another method. nothing to do
                    return
                if len(received) == 0:
                    #connection closed.
                    if self.readyState == 1:
                        self._conn_close()
                    return
                elif received == chr(0xFF)+chr(0x00): #closing handshake
                    #close handshake received
                    self._conn_close()
                    return
                else:
                    delimiter = received.find(chr(0xFF))+1
                    if delimiter > 0:
                        complete_frame = True
            if len(received) == 0:
                #tcp connection closed.
                if self.readyState == 1:
                    self._conn_close()
                return
            else:
                framed_data = received[:delimiter]
                data = self._unframe(framed_data)
                self.onmessage(self, data)
                received = received[delimiter:]
                complete_frame = False
        #connection not established!
        return


class WebsocketClient(WebsocketCommon):
    """This class implements a websocket client"""
    def _handshake(self, conn, host, path, proto):
        fields = {}
        conn_f = conn.makefile()
        (key1, number1) = self._generate_key()
        (key2, number2) = self._generate_key()
        key3 = self._gen_key3()
        origin = 'http://'+host
        _http_method = 'GET'
        _http_ver_string = 'HTTP/1.1'
        headers = _http_method+' '+path+' '+_http_ver_string+'\r\n'
        headers += 'Upgrade: WebSocket\r\n'
        headers += 'Connection: Upgrade\r\n'
        headers += 'Host: '+host+'\r\n'
        headers += 'Origin: '+origin+'\r\n'
        headers += 'Sec-WebSocket-Protocol: '+proto+'\r\n'
        headers += 'Sec-WebSocket-Key1: '+key1+'\r\n'
        headers += 'Sec-WebSocket-Key2: '+key2+'\r\n'
        headers += '\r\n'
        headers += key3
        conn.sendall(headers)
        response = conn_f.readline()
        if (len(response) < 7 or response.count(' ') < 2 or
            response[len(response)-2] != '\r' or
            response[len(response)-1] != '\n'):
            #according to the specification, fail the connection!
            print 'Websocket connection failed: invalid response'
            sys.exit(1)
        pos1 = response.find(' ')
        pos2 = pos1+4
        if pos1 == -1 or response[pos1+1:pos2] != '101':
            #according to the specification, fail the connection!
            #To-do: support response code 407 (proxy authentication)
            print 'Websocket connection failed: invalid response' 
            sys.exit(1)
        while True:
            field = conn_f.readline()
            if field == '\r\n':
                #done reading fields
                break
            field = field.strip('\r\n')
            colon_pos = field.find(':')
            field_name = field[:colon_pos]
            field_value = field[colon_pos+2:]
            fields[field_name.lower()] = field_value.lower()
        challenge_response = conn_f.read(16)
        self._fields_processing(conn, fields, proto, origin, number1, number2,
                                key3, challenge_response)
        return True

    def _fields_processing(self, conn, fields, subproto, origin, number1,
                           number2, key3, reply):
        conn_f = conn.makefile()
        if not 'connection' or not 'sec-websocket-origin' or not 'sec-websocket-location' or not 'sec-websocket-protocol' in fields:
            #according to the specification, fail the connection! - doesnt have the required fields
            print 'Websocket connection failed: necessary fields are absent.' 
            sys.exit(1)
        for field_name in fields:
            if field_name == 'upgrade' and fields[field_name] != 'websocket':
                #according to the specification, fail the connection! - upgrade value must be 'WebSocket'
                print 'Websocket connection failed: invalid response' 
                sys.exit(1)
            if field_name == 'connection' and fields[field_name].lower() != 'upgrade':
                #according to the specification, fail the connection! - connection value must be 'upgrade'
                print 'Websocket connection failed: invalid response' 
                sys.exit(1)
            if field_name == 'sec-websocket-origin' and fields[field_name].lower() != origin.lower():
                #according to the specification, fail the connection! - returned 'origin' value must be equal to value sent
                print 'Websocket connection failed: invalid response' 
                sys.exit(1)
            #TODO: check sec-websocket-location returned value
            #TODO: make protocol optional (only check if it was specified in the request)
            if field_name == 'sec-websocket-protocol' and fields[field_name] != subproto:
                #according to the specification, fail the connection! - returned 'protocol' value must be equal to value sent
                print 'Websocket connection failed: invalid response' 
                sys.exit(1)
            #TODO: support cookies
        challenge = self._bitfield(number1)+self._bitfield(number2)+key3
        expected = md5.new(challenge).digest() 
        if reply != expected:
            #according to the specification, fail the connection! - wrong challenge response
            print 'Websocket connection failed: incorrect challenge response' 
            sys.exit(1)
        #Connection established!
        self.readyState = 1
        return True

    def _generate_key(self):
        spaces = random.randint(1,12) #number of spaces
        maxi = 4294967295/spaces
        number = random.randint(0,maxi)
        product = number*spaces
        key = str(product)
        for i in range(1, spaces+1):
            #insert spaces at random positions
            pos = random.randint(0,len(key)-1)
            key = key[:pos]+' '+key[pos:]
        special = random.randint(1,12) #number of special chars
        spl_chars = '!"#$%&\'()*+,-./:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        for i in range(1, special+1):
            #insert special chars at random positions
            pos = random.randint(0,len(key)-1)
            char = random.choice(spl_chars)
            key = key[:pos]+char+key[pos:]
        return key, number

    def _gen_key3(self):
        key = ''
        for i in range(1,9):
            byte = random.randint(1,255)
            key += chr(byte)
        return key

    def __init__(self, url, subproto, open=None, message=None, error=None, close=None):
        url = urlparse(url)
        self.onopen = open
        self.onmessage = message
        self.onerror = error
        self.onclose = close
        self.conn = socket.create_connection((url.hostname, url.port))
        #TODO: gerar excecao em caso de erro de conexao...
        self._handshake(self.conn, url.hostname, url.path, subproto)
        if self.readyState != 1:
            #erro. conexao nao foi estabelecida
            print "Websocket handshake failed. Exiting"
            if self.onerror:
                self.onerror(conn)
            self.conn.close()
            sys.exit(1)
        elif self.onopen:
            self.onopen(self) #call onopen funcion if received
        if self.onmessage:
            thread.start_new_thread(self._receiver, ('', self.conn))
        return


class WebsocketServer(WebsocketCommon):
    """This class implements a Websocket server"""
    def _handshake(self, conn, port):
        fields = {}
        conn_f = conn.makefile()
        response = conn_f.readline()
        pos1 = response.find(' ')
        if response[:pos1] != 'GET':
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        response = response[pos1+2:]
        pos2 = response.find(' ')
        resource = response[:pos2]
        #reading fields
        while True:
            field = conn_f.readline()
            if field == '\r\n':
                #done reading fields
                break
            field = field.strip('\r\n')
            colon_pos = field.find(':')
            field_name = field[:colon_pos]
            field_value = field[colon_pos+2:]
            fields[field_name.lower()] = field_value.lower()
        key_3 = conn_f.read(8)
        #begin fields processing
        if not ('upgrade' in fields) or fields['upgrade'] != 'websocket':
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        if  not ('connection' in fields) or fields['connection'] != 'upgrade':
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        if  not ('host' in fields):
            #TODO: check the host value
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        if  not ('origin' in fields):
            #TODO: have the possibility to check the origin value against a list of
            # 'allowed' origins
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        #TODO: check the Sec-WebSocket-Protocol value in case a subprotocol was specified
        if not ('sec-websocket-key1' in fields):
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        if not ('sec-websocket-key2' in fields):
            #fail the connection
            print 'Websocket connection failed: invalid headers' 
            return False
        #begin the server's response
        location = fields['host']+':'+str(port)+'/'+resource
        key_number_1 = int(filter(lambda x: x in '0123456789', fields['sec-websocket-key1']))
        key_number_2 = int(filter(lambda x: x in '0123456789', fields['sec-websocket-key2']))
        spaces_1 = (fields['sec-websocket-key1']).count(' ')
        spaces_2 = (fields['sec-websocket-key2']).count(' ')
        if spaces_1 == 0 or spaces_2 == 0 or key_number_1%spaces_1 != 0 or key_number_2%spaces_2 != 0:
            #fail the connection
            print 'Websocket connection failed: invalid sec keys' 
            return False
        part_1 = key_number_1/spaces_1
        part_2 = key_number_2/spaces_2
        challenge = self._bitfield(part_1)+self._bitfield(part_2)+key_3
        response = md5.new(challenge).digest() 
        headers = 'HTTP/1.1 101 WebSocket Protocol Handshake\r\n'
        headers += 'Upgrade: WebSocket\r\n'
        headers += 'Connection: Upgrade\r\n'
        headers += 'Sec-WebSocket-Location: '+location+'\r\n'
        headers += 'Sec-WebSocket-Origin: '+fields['origin']+'\r\n'
        if 'sec-websocket-protocol' in fields:
            headers += 'Sec-WebSocket-Protocol: '+fields['sec-websocket-protocol']+'\r\n'
        headers += '\r\n'
        headers += response
        conn.sendall(headers)
        #Connection established!
        self.readyState = 1
        return True

    def __init__(self, connection, port, open=None, message=None, error=None, close=None):
        self.onopen = open
        self.onmessage = message
        self.onerror = error
        self.onclose = close
        self.conn = connection
        handshake_result = self._handshake(self.conn, port)
        if self.readyState != 1:
            #erro. conexao nao foi estabelecida
            print "Websocket handshake failed. Exiting"
            if self.onerror:
                onerror(self.conn)
            self.conn.close()
            sys.exit(1)
        elif self.onopen:
            self.onopen(self) #call onopen funcion if received
        if self.onmessage:
            #if an onmessage funcion was specified, start the receiver thread
            self._receiver('', self.conn)
        return
