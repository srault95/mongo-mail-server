#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Gevent SMTP Server based on https://github.com/34nm/gsmtpd
'''

__VERSION__ = "0.1.0"

from gevent.monkey import patch_all
patch_all()

import sys
import zlib
import base64
import datetime
import logging
import traceback
import smtplib
import uuid
import hashlib
from UserDict import UserDict
from ssl import CERT_NONE
import errno
from asynchat import find_prefix_at_end
import atexit
import os
import signal

from decouple import config as env_config

import gevent
from gevent import ssl
from gevent import socket, Timeout
from gevent.server import StreamServer

from dateutil import tz

__all__ = ["SMTPServer", "DebuggingServer", "PureProxy", 'SSLSettings', 
           'RecordPyMongoDBServer', 'RecordPyMongoDBServerProxy']

logger = logging.getLogger('mongo-mail-server')

NEWLINE = '\n'
EMPTYSTRING = ''
COMMASPACE = ', '

class SMTPChannel(object):
    """
    Port from stdlib smtpd used by Gevent
    """
    COMMAND = 0
    DATA = 1

    def __init__(self, server, conn, addr, data_size_limit=0, fqdn=None):
        self.server = server
        self.conn = conn
        self.addr = addr
        self.line = []
        self.state = self.COMMAND
        self.seen_greeting = 0
        self.mailfrom = None
        self.rcpttos = []
        self.data = ''
        self.fqdn = fqdn
        self.ac_in_buffer_size = 4096
        
        self.xforward_enable = True
        self.xforward_name = ''
        self.xforward_addr = ''
        self.xforward_helo = ''

        self.ac_in_buffer = ''
        self.closed = False
        self.data_size_limit = data_size_limit # in byte
        self.current_size = 0
        self.tls = False
        try:
            self.peer = conn.getpeername()
        except socket.error as err:
            # a race condition  may occur if the other end is closing
            # before we can get the peername
            logger.error(err)
            self.conn.close()
            if err[0] != errno.ENOTCONN:
                raise
            return
        self.push('220 %s SMTPD at your service' % self.fqdn)
        self.terminator = '\r\n'
        logger.debug('SMTP channel initialized')
        
    # Overrides base class for convenience
    def push(self, msg):
        logger.debug('PUSH %s' % msg)
        self.conn.send(msg + '\r\n')

    # Implementation of base class abstract method
    def collect_incoming_data(self, data):
        self.line.append(data)
        self.current_size += len(data)
        if self.data_size_limit > 0 and self.current_size > self.data_size_limit:
            self.push('452 Command has been aborted because mail too big')
            self.close_when_done()

    # Implementation of base class abstract method
    def found_terminator(self):
        line = EMPTYSTRING.join(self.line)
        self.line = []
        if self.state == self.COMMAND:
            if not line:
                self.push('500 Error: bad syntax')
                return
            method = None
            i = line.find(' ')
            if i < 0:
                command = line.upper().strip()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i+1:].strip()
            method = getattr(self, 'smtp_' + command, None)
            logger.debug('%s:%s', command, arg)
            if not method:
                self.push('502 Error: command "%s" not implemented' % command)
                return
            method(arg)
            return
        else:
            if self.state != self.DATA:
                self.push('451 Internal confusion')
                return
            # Remove extraneous carriage returns and de-transparency according
            # to RFC 821, Section 4.5.2.
            data = []
            for text in line.split('\r\n'):
                if text and text[0] == '.':
                    data.append(text[1:])
                else:
                    data.append(text)
            self.data = NEWLINE.join(data)
            
            xforward = {}
            
            if self.xforward_enable:
                xforward['NAME'] = self.xforward_name
                xforward['ADDR'] = self.xforward_addr
                xforward['HELO'] = self.xforward_helo
                logger.debug("XFORWARD NAME=%(NAME)s ADDR=%(ADDR)s HELO=%(HELO)s" % xforward)
            
            #peer, mailfrom, rcpttos, data, xforward
            status = self.server.process_message(self.peer,
                                                 self.mailfrom,
                                                 self.rcpttos,
                                                 self.data,
                                                 xforward)
            self.rcpttos = []
            self.mailfrom = None
            self.xforward_name = ''
            self.xforward_addr = ''
            self.xforward_helo = ''
            
            self.state = self.COMMAND
            self.terminator = '\r\n'
            if not status:
                self.push('250 Ok')
            else:
                self.push(status)
    
    # SMTP and ESMTP commands
    def smtp_HELO(self, arg):
        if not arg:
            self.push('501 Syntax: HELO hostname')
            return
        if self.seen_greeting:
            self.push('503 Duplicate HELO/EHLO')
        else:
            self.seen_greeting = arg
            self.push('250 %s' % self.fqdn)

    def smtp_EHLO(self, arg):
        if not arg:
            self.push('501 Syntax: EHLO hostname')
            return
        if self.seen_greeting:
            self.push('503 Duplicate HELO/EHLO')
        else:
            self.seen_greeting = arg
            self.extended_smtp = True
            if self.tls:
                self.push('250-%s on TLS' % self.fqdn)
            else:
                self.push('250-%s on plain' % self.fqdn)

            try:
                if self.server.ssl and not self.tls:
                    self.push('250-STARTTLS')
            except AttributeError:
                pass

            if self.data_size_limit > 0:
                self.push('250-SIZE %s' % self.data_size_limit)
            
            if self.xforward_enable:    
                #self.push('250-XFORWARD NAME ADDR HELO') #250-XFORWARD NAME ADDR PROTO HELO
                self.push('250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT')
                #amavis: XFORWARD NAME ADDR PORT PROTO HELO IDENT SOURCE
                #postfix: 250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT
            
            self.push('250 HELP')
    
    def smtp_NOOP(self, arg):
        if arg:
            self.push('501 Syntax: NOOP')
        else:
            self.push('250 Ok')

    def smtp_QUIT(self, arg=""):
        # args is ignored
        self.push('221 Bye')
        self.close_when_done()

    def smtp_TIMEOUT(self, arg=""):
        self.push('421 2.0.0 Bye')
        self.close_when_done()

    # factored
    def getaddr(self, keyword, arg):
        address = None
        keylen = len(keyword)
        if arg[:keylen].upper() == keyword:
            address = arg[keylen:].strip()
            if not address:
                pass
            elif address[0] == '<' and address[-1] == '>' and address != '<>':
                # Addresses can be in the form <person@dom.com> but watch out
                # for null address, e.g. <>
                address = address[1:-1]
        return address

    def smtp_XFORWARD(self, arg):
        
        """
        > support ESMTP postfix:
            250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT
        
        > support ESMTP mongomail:
            250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT
            
        > support ESMTP amavis:
            250 XFORWARD NAME ADDR PORT PROTO HELO SOURCE
        
        attribute-name = ( NAME | ADDR | PORT | PROTO | HELO | IDENT | SOURCE )
         > amavis sent:
         XFORWARD ADDR=209.85.213.175 NAME=mail-ig0-f175.google.com PORT=38689 PROTO=ESMTP HELO=mail-ig0-f175.google.com SOURCE=REMOTE
        """
        logger.debug('XFORWARD %s' % arg)
        
        if not arg:
            self.push('501 Syntax: XFORWARD')
        elif self.mailfrom:
            self.push('503 Error: XFORWARD after MAIL command')
            return
        else:
            attrs = arg.split(' ')

            for i in attrs:
                attr, value = i.split('=', 1)
                
                if attr == 'NAME':
                    self.xforward_name = value
                elif attr == 'ADDR':
                    self.xforward_addr = value
                elif attr == 'HELO':
                    self.xforward_helo = value

            self.push('250 Ok')

    def smtp_MAIL(self, arg):
        
        if not self.seen_greeting:
            self.push('503 Error: send HELO first');
            return
                
        address = self.getaddr('FROM:', arg.split()[0]) if arg else None
        if not address:
            self.push('501 Syntax: MAIL FROM:<address>')
            return
        if self.mailfrom:
            self.push('503 Error: nested MAIL command')
            return
        self.mailfrom = address
        self.push('250 Ok')

    def smtp_RCPT(self, arg):
        if not self.mailfrom:
            self.push('503 Error: need MAIL command')
            return
        address = self.getaddr('TO:', arg) if arg else None
        if not address:
            self.push('501 Syntax: RCPT TO: <address>')
            return
        
        result = self.server.process_rcpt(address)
        if not result:
            self.rcpttos.append(address)
            self.push('250 Ok')
        else:
            self.push(result)

    def smtp_RSET(self, arg):
        if arg:
            self.push('501 Syntax: RSET')
            return
        # Resets the sender, recipients, and data, but not the greeting
        self.mailfrom = None
        self.rcpttos = []
        self.data = ''
        self.xforward_name = ''
        self.xforward_addr = ''
        self.xforward_helo = ''
        self.state = self.COMMAND
        self.push('250 Ok')

    def smtp_DATA(self, arg):
        if not self.rcpttos:
            self.push('503 Error: need RCPT command')
            return
        if arg:
            self.push('501 Syntax: DATA')
            return
        self.state = self.DATA
        self.terminator = '\r\n.\r\n'
        self.push('354 End data with <CR><LF>.<CR><LF>')

    def smtp_STARTTLS(self, arg):

        if arg:
            self.push('501 Syntax: STARTTLS')
            return
        self.push('220 Ready to start TLS')
        
        if self.data:
            self.push('500 Too late to changed')
            return

        try:
            self.conn = ssl.wrap_socket(self.conn, **self.server.ssl)
            self.state = self.COMMAND
            self.seen_greeting = 0
            self.rcpttos = []
            self.mailfrom = None
            self.tls = True
        except Exception as err:
            logger.error(err, exc_info=True)
            self.push('503 certificate is FAILED')
            self.close_when_done()
    
    def smtp_HELP(self, arg):

        if arg:
            if arg == 'ME':
                self.push('504 Go to https://github.com/srault95/mongo-mail-server for help')
            else:
                self.push('501 Syntax: HELP')
        else:
            self.push('214 SMTP server is running...go to website for further help')

    def handle_read(self):
        try:
            data = self.conn.recv(self.ac_in_buffer_size)
            if len(data) == 0:
                # issues 2 TCP connect closed will send a 0 size pack
                self.close_when_done()
        except socket.error:
            self.handle_error()
            return

        self.ac_in_buffer = self.ac_in_buffer + data

        # Continue to search for self.terminator in self.ac_in_buffer,
        # while calling self.collect_incoming_data.  The while loop
        # is necessary because we might read several data+terminator
        # combos with a single recv(4096).

        while self.ac_in_buffer:
            lb = len(self.ac_in_buffer)
            logger.debug(self.ac_in_buffer)
            if not self.terminator:
                # no terminator, collect it all
                self.collect_incoming_data(self.ac_in_buffer)
                self.ac_in_buffer = ''
            elif isinstance(self.terminator, int) or isinstance(self.terminator, long):
                # numeric terminator
                n = self.terminator
                if lb < n:
                    self.collect_incoming_data(self.ac_in_buffer)
                    self.ac_in_buffer = ''
                    self.terminator = self.terminator - lb
                else:
                    self.collect_incoming_data (self.ac_in_buffer[:n])
                    self.ac_in_buffer = self.ac_in_buffer[n:]
                    self.terminator = 0
                    self.found_terminator()
            else:
                # 3 cases:
                # 1) end of buffer matches terminator exactly:
                #    collect data, transition
                # 2) end of buffer matches some prefix:
                #    collect data to the prefix
                # 3) end of buffer does not match any prefix:
                #    collect data
                terminator_len = len(self.terminator)
                index = self.ac_in_buffer.find(self.terminator)
                if index != -1:
                    # we found the terminator
                    if index > 0:
                        # don't bother reporting the empty string (source of subtle bugs)
                        self.collect_incoming_data (self.ac_in_buffer[:index])
                    self.ac_in_buffer = self.ac_in_buffer[index+terminator_len:]
                    # This does the Right Thing if the terminator is changed here.
                    self.found_terminator()
                else:
                    # check for a prefix of the terminator
                    index = find_prefix_at_end(self.ac_in_buffer, self.terminator)
                    if index:
                        if index != lb:
                            # we found a prefix, collect up to the prefix
                            self.collect_incoming_data (self.ac_in_buffer[:-index])
                            self.ac_in_buffer = self.ac_in_buffer[-index:]
                        break
                    else:
                        # no prefix, collect it all
                        self.collect_incoming_data(self.ac_in_buffer)
                        self.ac_in_buffer = ''
        
    def handle_error(self):
        self.close_when_done()

    def close_when_done(self):

        if not self.conn.closed:
            logger.debug('CLOSED %s' % self.conn)
            self.conn.close()
        self.closed = True

def load_plugin(name, callable_name='apply'):
    """Load module by name string
    
    >>> mod = load_plugin("rs_common.tools.python_tools")
    >>> hasattr(mod, callable_name)
    True 
    
    >>> "rs_common.tools.python_tools".split(".")[-1:]
    ['python_tools']
    
    >>> "rs_common.tools.python_tools".split(".")[:-1]
    ['rs_common', 'tools']    
    """
    
    if not name:
        return None

    module_name = name
    
    if not module_name in sys.modules:
        __import__(module_name)
        
    mod = sys.modules[module_name]
    
    if not hasattr(mod, callable_name):
        raise Exception("module [%s] not contains callable: %s" % (name,callable_name))
    
    method = getattr(mod, callable_name)
    
    if not callable(method):
        raise Exception("plugin not callable")
    
    return method
    

def compress(data):
    return base64.b64encode(zlib.compress(data))

def uncompress(data):
    return zlib.decompress(base64.b64decode(data))

def timestamp():
    dt = datetime.datetime.utcnow()
    return datetime.datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond, tz.tzutc())

def generate_key():
    """Génère un ID unique de 64 caractères"""
    new_uuid = str(uuid.uuid4())
    return hashlib.sha256(new_uuid).hexdigest()

def extract_real_recipients(data):
    from email.parser import HeaderParser
    from email.utils import getaddresses
    recipients = []
    try:
        msg = HeaderParser().parsestr(data, headersonly=True)
        getall = msg.get_all('X-Envelope-To', [])
        recipients = [r[1] for r in getaddresses(getall)]
    except Exception, err:
        logger.error(str(err))
    return recipients 
    
class ConnectionTimeout(BaseException):
    pass

class SSLSettings(UserDict):
    """SSL settings object"""
    def __init__(self, keyfile=None, certfile=None,
                 ssl_version='PROTOCOL_SSLv23', ca_certs=None,
                 do_handshake_on_connect=True, cert_reqs=CERT_NONE,
                 suppress_ragged_eofs=True, ciphers=None, **kwargs):
        """settings of SSL

        :param keyfile: SSL key file path usally end with ".key"
        :param certfile: SSL cert file path usally end with ".crt"
        """
        UserDict.__init__(self) 
        self.data.update( dict(keyfile = keyfile,
                                certfile = certfile,
                                server_side = True,
                                ssl_version = getattr(ssl, ssl_version, ssl.PROTOCOL_SSLv23),
                                ca_certs = ca_certs,
                                do_handshake_on_connect = do_handshake_on_connect,
                                cert_reqs=cert_reqs,
                                suppress_ragged_eofs = suppress_ragged_eofs,
                                ciphers = ciphers))


class SMTPServer(StreamServer):
    """Abstracted SMTP server
    """

    def __init__(self, localaddr=None, remoteaddr=None, 
                 timeout=60, data_size_limit=0, fqdn=None, debug=False, plugins=[], **kwargs):
        """Initialize SMTP Server

        :param localaddr: tuple pair that start server, like `('127.0.0.1', 25)`
        :param remoteaddr: ip address (string or list) that can relay on this server
        :param timeout: int that connection Timeout
        :param data_size_limit: max byte per mail data
        :param kwargs: other key-arguments will pass to :class:`.SSLSettings`
        """

        self.relay = bool(remoteaddr)
        self.remoteaddr = remoteaddr
        
        self.localaddr = localaddr

        if not self.localaddr:
            self.localaddr = ('127.0.0.1', 25)
        
        self.ssl = None
        
        self.timeout = int(timeout)

        self.data_size_limit = int(data_size_limit)
        
        self.fqdn = fqdn or socket.getfqdn()
        
        self._plugins = plugins
        
        self.debug = debug

        if 'keyfile' in kwargs:
            self.ssl = SSLSettings(**kwargs)

        super(SMTPServer, self).__init__(self.localaddr, self.handle)

    def handle(self, sock, addr):

        logger.debug('Incomming connection %s:%s', *addr[:2])

        if self.relay and not addr[0] in self.remoteaddr:
            logger.debug('Not in remoteaddr', *addr[:2])
            return 
        try:
            with Timeout(self.timeout, ConnectionTimeout):
                sc = SMTPChannel(self, sock, addr, 
                                 data_size_limit=self.data_size_limit, 
                                 fqdn=self.fqdn,
                                 )
                while not sc.closed:
                    sc.handle_read()

        except ConnectionTimeout:
            logger.warn('%s:%s Timeouted', *addr[:2])
            try:
                sc.smtp_TIMEOUT()
            except Exception as err:
                logger.debug(err)
        except Exception as err:
            logger.error(err)

    # API for "doing something useful with the message"
    def process_message(self, peer, mailfrom, rcpttos, data, xforward):
        """Override this abstract method to handle messages from the client.

        :param peer: is a tuple containing (ipaddr, port) of the client that made\n
                     the socket connection to our smtp port.
        :param mailfrom: is the raw address the client claims the message is coming from.
        :param rcpttos: is a list of raw addresses the client wishes to deliver the message to.
        :param data: is a string containing the entire full text of the message,\n
                     headers (if supplied) and all.  It has been `de-transparencied'\n
                     according to RFC 821, Section 4.5.2.\n
                     In other words, a line containing a `.' followed by other text has had the leading dot
        removed.

        This function should return None, for a normal `250 Ok' response;
        otherwise it returns the desired response string in RFC 821 format.

        """
        raise NotImplementedError
    
    # API that handle rcpt
    def process_rcpt(self, address):
        """Override this abstract method to handle rcpt from the client

        :param address: is raw address the client wishes to deliver the message to

        This function should return None, for a normal `250 Ok' response;
        otherwise it returns the desired response string in RFC 821 format.
        """
        pass

class DebuggingServer(SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data, xforward):

        d = dict(store_key=None, 
                 sender=mailfrom.strip().lower(),
                 rcpt=rcpttos, 
                 rcpt_count=len(rcpttos),
                 client_address=xforward.get('ADDR', ''),
                 xforward=xforward,
                 server=peer[0],
                 received=timestamp(),
                 rcpt_refused={})

        if self._plugins:
            for plugin in self._plugins:
                logger.debug("run plugin[%s]" % plugin)
                plugin(metadata=d, data=data)
                
        print "debug server process_message..."
        inheaders = 1
        lines = data.split('\n')
        print '---------- MESSAGE FOLLOWS ----------'
        for line in lines:
            # headers first
            if inheaders and not line:
                print 'X-Peer:', peer[0]
                inheaders = 0
            print line
        print '------------ END MESSAGE ------------'


class PureProxy(SMTPServer):
    
    def process_message(self, peer, mailfrom, rcpttos, data, xforward):
        lines = data.split('\n')
        # Look for the last header
        i = 0
        for line in lines:
            if not line:
                break
            i += 1
        lines.insert(i, 'X-Peer: %s' % peer[0])
        data = NEWLINE.join(lines)
        refused = self._deliver(mailfrom, rcpttos, data)
        # TBD: what to do with refused addresses?
        logger.debug('we got some refusals: %s', refused)

    def _deliver(self, mailfrom, rcpttos, data):
        refused = {}
        try:
            s = smtplib.SMTP()
            s.connect(self.remoteaddr[0], self.remoteaddr[1])
            try:
                refused = s.sendmail(mailfrom, rcpttos, data)
            finally:
                s.quit()
        except smtplib.SMTPRecipientsRefused, e:
            logger.debug('got SMTPRecipientsRefused')
            refused = e.recipients
        except (socket.error, smtplib.SMTPException), e:
            logger.debug( 'got %s', e.__class__)
            # All recipients were refused.  If the exception had an associated
            # error code, use it.  Otherwise,fake it with a non-triggering
            # exception code.
            errcode = getattr(e, 'smtp_code', -1)
            errmsg = getattr(e, 'smtp_error', 'ignore')
            for r in rcpttos:
                refused[r] = (errcode, errmsg)
        return refused

class RecordPyMongoDBServer(SMTPServer):
    """Record message to Mongo Server"""
    
    def __init__(self, 
                 allow_hosts=[],
                 db=None,
                 colname=None,
                 real_rcpt=False,
                 **kwargs):
        
        SMTPServer.__init__(self, **kwargs)
        
        self._allow_hosts = allow_hosts
        
        self.db = db
        self.colname = colname
        self.real_rcpt = real_rcpt
        
        self.col = self.db[self.colname]
        from gridfs import GridFS
        self.fs = GridFS(self.db)
        
    def _security_check(self, address):
        """
        fail2ban: 2015-02-21 09:57:05 [5972] [CRITICAL] reject host [127.0.0.1]
        """
        
        if not self._allow_hosts:
            return True
        
        try:
            host = address[0]

            if not host in self._allow_hosts:
                logger.critical("reject host [%s]" % host)
                return False
            
            return True
            
        except Exception, err:
            logger.error(str(err))
        
        return False

    def handle(self, sock, addr):
        
        if not self._security_check(addr):                
            sock.close()
            return
        
        return SMTPServer.handle(self, sock, addr)

    def _record_mongodb(self, peer, mailfrom, rcpttos, data, xforward, refused=None):
        """
        - pour search with reader:
        TODO: extract ('X-Quarantine-ID', '<QX1Er+4cACI0>')
        TODO: extract ('Message-ID', '<CAL1AQgSvrDtem3v8hK4dVWKYprcmo9kxyOVjyv9=txe7yRD_Og@mail.gmail.com>')
        """

        key = generate_key()
        
        recipients = []
        
        if len(rcpttos) == 1 and self.real_rcpt:
            recipients = extract_real_recipients(data)
            lines = data.split('\n')
            rcpt_header = "X-MMS-RCPT: <%s>" % rcpttos[0]
            lines.insert(0, rcpt_header)
            data = "\n".join(lines)
        else:
            for r in rcpttos:
                recipients.append(r.strip().lower())
        
        d = dict(store_key=key, 
                 sender=mailfrom.strip().lower(), 
                 rcpt=recipients, 
                 rcpt_count=len(recipients),
                 client_address=xforward.get('ADDR', ''),
                 xforward=xforward,
                 server=peer[0],
                 received=timestamp(),
                 rcpt_refused=refused or {})

        if self._plugins:
            for plugin in self._plugins:
                logger.debug("run plugin[%s]" % plugin)
                plugin(metadata=d, data=data)
        
        message = self.fs.put(compress(data),
                              filename=key, 
                              #content_type='message/rfc822',
                              content_type='text/plain',                                  
                              )
        d['message'] = message
        
        from pprint import pprint
        #pprint(d)
        
        self.col.insert(d)
        
        return key 
    
        
    def process_message(self, peer, mailfrom, rcpttos, data, xforward):
        try:
            key = self._record_mongodb(peer, mailfrom, rcpttos, data, xforward)
            
            msg = "250 Ok: queued as %s" % key
            
            logger.info(msg)
            
            data = None
            key = None
            xforward = None
            
            return msg
        
        except Exception, err:
            logger.error(str(err))
            return "400 Server Error"
        
class RecordPyMongoDBServerProxy(RecordPyMongoDBServer):

    def process_message(self, peer, mailfrom, rcpttos, data, xforward):
        
        try:
            refused = self._deliver(mailfrom, rcpttos, data, xforward)
            
            key = self._record_mongodb(peer, mailfrom, rcpttos, data, xforward, refused)
            msg = "250 Ok: queued as %s" % key
            logger.info(msg)
            
            data = None
            key = None
            xforward = None
            
            return msg
        
        except Exception, err:
            logger.error(str(err))
            return "400 Server Error"

    def _deliver(self, mailfrom, rcpttos, data, xforward):
        refused = {}
        try:
            s = smtplib.SMTP(host=self.remoteaddr[0], port=self.remoteaddr[1])
            if self.debug:
                s.set_debuglevel(1)
            s.does_esmtp = 1
            
            try:

                (code, msg) = s.ehlo()
                if code != 250:
                    s.rset()
                    raise smtplib.SMTPHeloError(code, msg)
        
                (code, msg) = s.docmd('XFORWARD', 'ADDR=%(ADDR)s NAME=%(NAME)s HELO=%(HELO)s' % xforward)
                if code != 250:
                    s.rset()
                    raise smtplib.SMTPResponseException(code, msg)
                
                (code, msg) = s.mail(mailfrom)#, ["size=%s" % len(data)])
                if code != 250:
                    s.rset()
                    raise smtplib.SMTPSenderRefused(code, msg, mailfrom)
                
                for rcpt in rcpttos:
                    (code, msg) = s.rcpt(rcpt)
                    if not code in [250, 251]:
                        refused[rcpt] = (code, msg)
                        
                if len(refused) == len(rcpttos):
                    s.rset()
                    raise smtplib.SMTPRecipientsRefused(refused)
                
                (code, msg) = s.data(data)
                if code != 250:
                    s.rset()
                    raise smtplib.SMTPDataError(code, msg)

            finally:
                s.quit()
                
        except smtplib.SMTPRecipientsRefused, e:
            logger.debug('got SMTPRecipientsRefused')
            refused = e.recipients
        except (socket.error, smtplib.SMTPException), e:
            logger.debug( 'got %s', e.__class__)
            # All recipients were refused.  If the exception had an associated
            # error code, use it.  Otherwise,fake it with a non-triggering
            # exception code.
            errcode = getattr(e, 'smtp_code', -1)
            errmsg = getattr(e, 'smtp_error', 'ignore')
            for r in rcpttos:
                refused[r] = (errcode, errmsg)
        
        return refused

"""
('X-Envelope-From', '<stephane.rault@radicalspam.org>')
('X-Envelope-To', '<contact@mail-analytics.net>')
('X-Envelope-To-Blocked', '')
('X-Quarantine-ID', '<QX1Er+4cACI0>')
('X-Spam-Flag', 'NO')
('X-Spam-Score', '-100.126')
('X-Spam-Level', '')
('X-Spam-Status', 'No, score=-100.126 tag=-999 tag2=8 kill=8 tests=[BAYES_00=-1.9,\n\tDKIM_SIGNED=0.1, DKIM_VALID=-0.1, DKIM_VALID_AU=-0.1,\n\tFM_FORGED_GMAIL=0.622, GMD_PDF_STOX_M5=1, GMD_PRODUCER_GPL=0.25,\n\tHTML_MESSAGE=0.001, SPF_PASS=-0.001, TVD_SPACE_RATIO=0.001,\n\tURIBL_BLOCKED=0.001, USER_IN_WHITELIST=-100] autolearn=no')
('Received', 'from mx1.radical-spam.fr ([127.0.0.1])\n\tby localhost (mx1.radical-spam.fr [127.0.0.1]) (amavisd-new, port 10039)\n\twith ESMTP id QX1Er+4cACI0 for <contact@mail-analytics.net>;\n\tMon,  6 Apr 2015 12:02:19 +0200 (CEST)')
('Received', 'from mail-ig0-f171.google.com (mail-ig0-f171.google.com [209.85.213.171])\n\tby mx1.radical-spam.fr (Postfix) with ESMTP id 4CA2F4620C8\n\tfor <contact@mail-analytics.net>; Mon,  6 Apr 2015 12:02:19 +0200 (CEST)')
('Received', 'by igbqf9 with SMTP id qf9so16118895igb.1\n        for <contact@mail-analytics.net>; Mon, 06 Apr 2015 03:02:34 -0700 (PDT)')
('DKIM-Signature', 'v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=radicalspam.org; s=google;\n        h=mime-version:from:date:message-id:subject:to:content-type;\n        bh=iHjvyFOWXJ02+bFfv5m1O3eujdZg5uNjMWhbQ/J8GHU=;\n        b=DX3j5LO4VIHSoVi9ZUt6rB8MlglJJc0yTbR+NEpCG3BHkwlGtNF4bnM6hzo65kF00s\n         VW00r2UFChO62xfp2DjTQs0VPL3JEg04nOdBiCfyWBZiaqtA6z5FA0FjYOtHdKn7rpe2\n         P1NbNIBspmDQxqph8PMU3UG89SBcudrTHC8QI=')
('X-Received', 'by 10.50.30.202 with SMTP id u10mr21997931igh.28.1428314554187;\n Mon, 06 Apr 2015 03:02:34 -0700 (PDT)')
('Received', 'by 10.36.9.137 with HTTP; Mon, 6 Apr 2015 03:02:03 -0700 (PDT)')
('X-Originating-IP', '[88.175.183.38]')
('From', '=?UTF-8?Q?St=C3=A9phane_RAULT?= <stephane.rault@radicalspam.org>')
('Date', 'Mon, 6 Apr 2015 12:02:03 +0200')
('Message-ID', '<CAL1AQgSvrDtem3v8hK4dVWKYprcmo9kxyOVjyv9=txe7yRD_Og@mail.gmail.com>')
('Subject', 'test2')
('To', 'contact <contact@mail-analytics.net>')
('Content-Type', 'multipart/mixed; boundary=047d7b874b2ca17a8c05130b657a')

        docker exec -it mms1 python
        >>> import os, zlib, base64
        >>> from pprint import pprint as pp
        >>> from email.parser import Parser, HeaderParser
        >>> from pymongo import MongoClient
        >>> from gridfs import GridFS
        >>> client = MongoClient(os.environ.get('MMS_MONGODB_URI'))
        >>> db = client['message']
        
        #>>> db.drop_collection('message')
        #>>> db.drop_collection('fs.files')
        #>>> db.drop_collection('fs.chunks')
        
        >>> col = db['message']
        >>> doc = col.find_one() 

        >>> fs = GridFS(db)
        >>> fs.list()
        [u'77dd50277b8b6260c9bda483ab12fb2c25a1c94337978310b7e8546cdf63ebf2']
        
        >>> msg_base64 = fs.get(doc['message']).read()
        >>> msg_string = zlib.decompress(base64.b64decode(msg_base64))
        >>> msg = Parser().parsestr(msg_string)
        >>> for header in msg._headers: print header

"""

class MongoMailReader(object):
    
    def __init__(self, 
                 db=None,
                 colname=None,
                 **kwargs):
        
        self.db = db
        self.colname = colname
        self.col = self.db[self.colname]
        from gridfs import GridFS
        self.fs = GridFS(self.db)
        
    def count(self):
        return self.col.count()
    
    def field_keys(self):
        count = self.count()
        if count == 0:
            return []
        doc = self.col.find_one()
        return doc.keys()
    
    def file_list(self):
        return self.fs.list()
    
    def display_headers(self, message_id, headers=[]):
        from email.parser import HeaderParser
        """
        >>> msg_base64 = fs.get(doc['message']).read()
        >>> msg_string = zlib.decompress(base64.b64decode(msg_base64))
        >>> msg = Parser().parsestr(msg_string)
        >>> for header in msg._headers: print header
        """
        result = {}
        msg = HeaderParser().parsestr(zlib.decompress(base64.b64decode(self.fs.get(message_id).read())))
        for header, value in msg._headers:
            if not header in headers:
                continue
            
            if header in result:
                result[header] = [result[header]] + [value]
            else:
                result[header] = value 
        return result

    def display_as_string(self, store_key=None):
        doc = self.col.find_one({'store_key': {'$eq': store_key} })
        if doc:
            message_id = doc['message']
            return zlib.decompress(base64.b64decode(self.fs.get(message_id).read()))

def reader_options():
    import argparse

    parser = argparse.ArgumentParser(description='Mongo Mail Reader',
                                     formatter_class=argparse.RawTextHelpFormatter, 
                                     prog=os.path.basename(sys.argv[0]),
                                     version=__VERSION__, 
                                     add_help=True)
    
    parser.add_argument(
        '--mongo-host',
        default=env_config('MMS_MONGODB_URI', 'mongodb://localhost/message'),
        dest='mongo_host',
        help='MongoDB URI.  Defaults to %(default)s'
    )
        
    parser.add_argument(
        '--mongo-database',
        default=env_config('MMS_MONGODB_DATABASE', 'message'),
        dest='mongo_database',
        help='Mongod database.  Defaults to %(default)s'
    )
    
    parser.add_argument(
        '--mongo-collection',
        default=env_config('MMS_MONGODB_COLLECTION', 'message'),
        dest='mongo_collection',
        help='Mongod collection.  Defaults to %(default)s'
    )

    parser.add_argument(
        '--fields',
        default='received,client_address,sender',
        dest='fields',        
        help='Display fields.  Defaults to %(default)s'
    )

    parser.add_argument(
        '--headers',
        default=None,
        dest='headers',        
        help='Display headers in message'
    )

    parser.add_argument(
        '--order-by',
        default='received',
        dest='order_by',        
        help='Order By.  Defaults to %(default)s'
    )

    parser.add_argument(
        '--store-key',
        dest='store_key',        
        help='store_key field for search one document.'
    )

    parser.add_argument(
        '--date-format',
        default='%Y-%m-%d %H:%M:%S',
        dest='date_format',        
        help='Date formatter.  Defaults to %(default)s'
    )

    parser.add_argument(
        '--order-desc',
        action="store_true",
        dest='order_desc',
    )
    
    parser.add_argument(
        '--limit',
        default=0,
        type=int,
        help='Diplay limit (zero for no limit).  Defaults to %(default)s'
    )
    

    commands = ['count', 
                'display', 
                'fields',
                #'status',
                'one', 
                #'reload', 
    ]    

    parser.add_argument(choices=commands,
                        dest='command',
                        help="Run command.")
    
    parser.add_argument('--debug', 
                        action="store_true",
                        default=env_config('MMS_DEBUG', False, cast=bool)
                        )

    parser.add_argument('--json', 
                        action="store_true",
                        default=False,
                        )

    parser.add_argument('--pretty', 
                        action="store_true",
                        default=False,
                        )
        
    args = parser.parse_args()
       
    kwargs = dict(args._get_kwargs())
    
    return kwargs

        
def main_reader():
    opts = reader_options()
    command = opts.get('command')
    debug = opts.get('debug', False)
    mongo_host = opts.get('mongo_host')
    mongo_database = opts.get('mongo_database')
    mongo_collection = opts.get('mongo_collection')
    fields = opts.get('fields').split(',')
    headers = opts.get('headers')
    order_by = opts.get('order_by')
    order_desc = opts.get('order_desc')
    limit = opts.get('limit')
    date_format = opts.get('date_format')
    is_json = opts.get('json')
    is_pretty = opts.get('pretty')
    store_key = opts.get('store_key', None)
    configure_logging(verbose=debug, frontend=True, prog_name='mongo-mail-server')

    MONGODB_SETTINGS = {
        'host': mongo_host,
        'use_greenlets': True,
        'tz_aware': True,
    }        
    
    from pprint import pprint as pp
    import json
    import pymongo
    from pymongo import MongoClient
    from bson import ObjectId 
    client = MongoClient(**MONGODB_SETTINGS)
    
    def json_convert(obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime.datetime):
            return str(obj.isoformat())        
        return obj
    
    reader = MongoMailReader(db=client[mongo_database], colname=mongo_collection)
    
    def datetime_format(values):
        new_values = values.copy()
        for key, value in values.items():
            if isinstance(value, datetime.datetime):
                new_values[key] = value.strftime(date_format)
        return new_values      
    
    if command == 'count':
        count = reader.count()
        if is_json:
            print json.dumps(dict(count=count))
        else: 
            print "%d documents" % count
    elif command == 'fields':
        fields = reader.field_keys()
        if is_json:
            print json.dumps(dict(fields=fields))
        else: 
            print ",".join(fields)
    elif command == 'one':
        msg_string = reader.display_as_string(store_key)
        print msg_string        
    elif command == 'display':
        _headers = None
        if headers:
            _headers = headers.split(',')
            fields.append('message')
        query = {}
        order = pymongo.ASCENDING
        if order_desc:
            order = pymongo.DESCENDING
        col_result = reader.col.find(query, fields=fields).sort(order_by, order)

        if limit > 0:
            col_result = col_result.limit(limit)
        for doc in col_result:
            values = doc
            if _headers:
                _h = reader.display_headers(doc['message'], _headers)
                values['headers'] = _h
            
            if "message" in values:
                values.pop('message')
            
            if is_pretty:
                values = datetime_format(values)
                pp(values)
            elif is_json:
                print json.dumps(values, default=json_convert)
            else:
                values = datetime_format(values)
                print values 
            
        
        
            
        
def configure_logging(verbose=False, 
                      frontend=True, 
                      add_syslog=False,
                      prog_name=__package__
                      ):
    """Configuration logging syslog sauf si win32"""
    
    #from logging.handlers import SysLogHandler
    
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': True,
        'formatters': {
            'verbose': {
                'format': '%(asctime)s %(name)s: [%(levelname)s] - [%(process)d] - [%(module)s] - %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
            'simple': {
                'format': '%(asctime)s %(name)s: [%(levelname)s] - %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
        },    
        'handlers': {
            'null': {
                'level':'ERROR',
                'class':'logging.NullHandler',
            },
            'console':{
                'level':'INFO',
                'class':'logging.StreamHandler',
                'formatter': 'simple'
            },       
            #'syslog':{
            #    #'level':'INFO',
            #    'class':'logging.handlers.SysLogHandler',
            #    'address' : '/dev/log',
            #    'facility': SysLogHandler.LOG_DAEMON,
            #    'formatter': 'simple'    
            #},       
        },
        'loggers': {
            prog_name: {
                #'handlers': ['syslog'],
                'handlers': ['console'],
                'level': 'INFO',
                'propagate': True,
            },
        },
    }
    
    if sys.platform.startswith("win32"):
        #Si windows remplacer par console
        LOGGING['loggers'][prog_name]['handlers'] = ['console']
        #del LOGGING['handlers']['syslog']
        if verbose:
            LOGGING['loggers'][prog_name]['level'] = 'DEBUG'
            LOGGING['handlers']['console']['formatter'] = 'verbose'
            LOGGING['handlers']['console']['level'] = 'DEBUG'
        
    elif frontend:
        #Si frontend, ajouter console
        if not 'console' in LOGGING['loggers'][prog_name]['handlers']:
            LOGGING['loggers'][prog_name]['handlers'].append('console')
        
        if verbose:
            #Si verbose, ajouter console et remplacer formatter
            LOGGING['loggers'][prog_name]['level'] = 'DEBUG'
            #LOGGING['handlers']['syslog']['formatter'] = 'verbose'
            LOGGING['handlers']['console']['formatter'] = 'verbose'
            LOGGING['handlers']['console']['level'] = 'DEBUG'
    
    #import pprint
    #pprint.pprint(LOGGING)
    
    import logging.config
    logging.config.dictConfig(LOGGING)
    logger = logging.getLogger(prog_name)
    
    return logger

SERVERS = {
    'debug': DebuggingServer,
    'mongo-proxy': RecordPyMongoDBServerProxy,
    'mongo-quarantine': RecordPyMongoDBServer,
    'mongo-filter': RecordPyMongoDBServer,
    #'es-quarantine': '',
}
    
def options():
    import argparse

    parser = argparse.ArgumentParser(description='Mongo Mail SMTP Server',
                                     formatter_class=argparse.RawTextHelpFormatter, 
                                     prog=os.path.basename(sys.argv[0]),
                                     version=__VERSION__, 
                                     add_help=True)
    
    parser.add_argument(
        '--host',
        default=env_config('MMS_HOST', "0.0.0.0"),
        help='Local address to attach to for receiving mail.  Defaults to %(default)s'
    )
        
    parser.add_argument(
        '--port',
        default=env_config('MMS_PORT', 14001, cast=int),
        type=int,
        help='Local port to attach to for receiving mail.  Defaults to %(default)s'
    )

    parser.add_argument(
        '--remote-host',
        default=env_config('MMS_REMOTE_HOST', "127.0.0.1"),
        help='remote address to sent mail (proxy mode only).  Defaults to %(default)s'
    )
        
    parser.add_argument(
        '--remote-port',
        default=env_config('MMS_REMOTE_PORT', 14002, cast=int),
        type=int,
        help='remote port to sent mail (proxy mode only).  Defaults to %(default)s'
    )

    parser.add_argument(
        '--concurency',
        default=env_config('MMS_CONCURENCY', 50, cast=int),
        dest='spawn',
        type=int,
        help='SMTPD Concurency.  Defaults to %(default)s')
    
    parser.add_argument(
        '--max-connections',
        default=env_config('MMS_MAX_CONNECTIONS', 256, cast=int),
        dest='backlog',
        type=int,
        help='SMTPD Max Clients.  Defaults to %(default)s')

    parser.add_argument(
        '--timeout',
        default=env_config('MMS_TIMEOUT', 600, cast=int),
        dest='timeout',
        type=int,
        help='SMTPD Timeout (seconds). Defaults to %(default)s')
    
    parser.add_argument(
        '--data-size-limit',
        default=env_config('MMS_DATA_SIZE_LIMIT', 0, cast=int),
        dest='data_size_limit',
        type=int,
        help='SMTPD Data Size Limit (octets) - Zero for no limit.  Defaults to %(default)s')

    server_args = parser.add_argument('--server',
                        choices=SERVERS.keys(),
                        default=env_config('MMS_SERVER', 'mongo-quarantine'),
                        dest='server_choice',
                        help="Server type choice. Defaults to %(default)s")
    
    parser.add_argument(
        '--mongo-host',
        default=env_config('MMS_MONGODB_URI', 'mongodb://localhost/message'),
        dest='mongo_host',
        help='MongoDB URI.  Defaults to %(default)s'
    )
        
    parser.add_argument(
        '--mongo-database',
        default=env_config('MMS_MONGODB_DATABASE', 'message'),
        dest='mongo_database',
        help='Mongod database.  Defaults to %(default)s'
    )
    
    parser.add_argument(
        '--mongo-collection',
        default=env_config('MMS_MONGODB_COLLECTION', 'message'),
        dest='mongo_collection',
        help='Mongod collection.  Defaults to %(default)s'
    )
    
    allow_arg = parser.add_argument('--allow', 
                        dest='allow_hosts',
                        metavar="path",
                        action="append",
                        default=[], 
                        help='Allow hosts'
                        )
    
    plugins = parser.add_argument('--plugin', 
                        dest='plugins',
                        metavar="path",
                        action="append",
                        default=[], 
                        help='Plugins packages contains apply() method'
                        )
    
    commands = ['start', 
                #'stop', 
                #'status', 
                #'reload', 
    ]    

    parser.add_argument(choices=commands,
                        dest='command',
                        help="Run command.")

    parser.add_argument('--debug', 
                        action="store_true",
                        default=env_config('MMS_DEBUG', False, cast=bool)
                        )
    
    parser.add_argument('--real-rcpt', 
                        action="store_true",
                        dest='real_rcpt',
                        default=env_config('MMS_REAL_RCPT', False, cast=bool)
                        )
        
    args = parser.parse_args()
       
    kwargs = dict(args._get_kwargs())
    
    return kwargs


def signal_server_stop(*args, **kwargs):
    server.stop()
    
def atexit_server_stop(server):
    server.stop()
    
def command_start(mode=None,
                  localaddr=None,
                  remoteaddr=None,
                  backlog=256, 
                  spawn='default',
                  timeout=30, 
                  data_size_limit=0, 
                  mongo_host=None, 
                  mongo_database='message', 
                  mongo_collection='message',
                  allow_hosts=None,
                  server_choice=None,
                  real_rcpt=False,
                  plugins=[],           
                  debug=False):

    try:
        MONGODB_SETTINGS = {
            'host': mongo_host,
            #'username': None,
            #'password': None,
            'use_greenlets': True,
            'tz_aware': True,
        }        
        
        from pymongo import MongoClient 
        
        client = MongoClient(**MONGODB_SETTINGS)        
        
        #TODO: timeout connection, timeout_data et timeout_global
        
        server_class = None
        
        pid = str(os.getpid())
        
        server_class = SERVERS[server_choice]
        
        _plugins = []
        if plugins and len(plugins) > 0:
            for plugin in plugins:
                c = load_plugin(plugin)
                _plugins.append(c)
        
        if server_choice == 'debug':

            server_kwargs = dict(localaddr=localaddr,
                                 timeout=timeout,
                                 backlog=backlog,
                                 spawn=spawn, 
                                 data_size_limit=data_size_limit,
                                 plugins=_plugins,
                                 debug=debug)
            
            msg = "Starting SMTP Server - server[%s] - on %s:%s (PID:%s)" % (server_choice, localaddr[0], localaddr[1], pid)
        
        elif server_choice in ['mongo-quarantine', 'mongo-filter']:
            
            server_kwargs = dict(localaddr=localaddr,
                                 allow_hosts=allow_hosts,
                                 plugins=_plugins,                                       
                                 timeout=timeout,
                                 backlog=backlog,
                                 spawn=spawn, 
                                 data_size_limit=data_size_limit, 
                                 db=client[mongo_database],
                                 colname=mongo_collection,
                                 debug=debug)
            
            if server_choice == 'mongo-quarantine':
                server_kwargs['real_rcpt'] = real_rcpt
            
            msg = "Starting SMTP Server - server[%s] - on %s:%s (PID:%s)" % (server_choice, localaddr[0], localaddr[1], pid)
            
        elif server_choice == 'mongo-proxy':
            
            server_kwargs = dict(localaddr=localaddr,
                                 remoteaddr=remoteaddr,
                                 allow_hosts=allow_hosts,
                                 plugins=_plugins,                                       
                                 timeout=timeout,
                                 backlog=backlog,
                                 spawn=spawn, 
                                 data_size_limit=data_size_limit, 
                                 db=client[mongo_database],
                                 colname=mongo_collection,
                                 debug=debug,                                     )

            msg = "Starting SMTP Server - server[%s] - on %s:%s -> remote %s:%s (PID:%s)" % (server_choice,
                                                                                           localaddr[0], localaddr[1], 
                                                                                           remoteaddr[0], remoteaddr[1], 
                                                                                           pid)
         
        server = server_class(**server_kwargs)
        
        if allow_hosts:
            msg = "%s - allow[%s]" % (msg, ",".join(allow_hosts))
        logger.info(msg)
        
        #gevent.signal(signal.SIGTERM, signal_server_stop)
        #if hasattr(signal, 'SIGQUIT'): gevent.signal(signal.SIGQUIT, signal_server_stop)
        
        atexit.register(atexit_server_stop, server)
        
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
        sys.exit(0)
    except Exception, err:
        sys.stderr.write("Start Server Error : %s\n" % str(err))
        sys.exit(1)
        
def main():
    
    opts = options()
    command = opts.pop('command')    
    debug = opts.pop('debug', False)
    """
    With plugins:
        python -m mongo_mail_server --server debug --host 127.0.0.1 --port 14001 --plugin contrib.dummy_plugin start    
    
    debug server:
        python -m mongo_mail_server --server debug --host 127.0.0.1 --port 14001 start 
    
    mongo filter or quarantine
        python -m mongo_mail_server --server mongo-quarantine start
    
    mongo proxy:
        python -m mongo_mail_server --host 127.0.0.1 --port 14002 --server debug start
        python -m mongo_mail_server --remote-host 127.0.0.1 --remote-port 14002 --server mongo-proxy start
        
    reader:
        /usr/local/bin/mongo-mail-reader --limit 10 --order-desc --headers Received --pretty display
        --pretty, --json
        
        --limit 10 --order-desc --order-by rcpt_count --headers To --pretty display
        
        #list of store_key
        --fields received,sender,store_key --limit 10 --order-desc --pretty

        #extract message string
        --store-key xxx one
    """
    
    configure_logging(verbose=debug, frontend=True, prog_name='mongo-mail-server')
    
    if command == 'start':
        
        localaddr = (opts.pop('host'), opts.pop('port'))
        
        remoteaddr = (opts.pop('remote_host'), opts.pop('remote_port'))
    
        command_start(localaddr=localaddr,
                      remoteaddr=remoteaddr,
                      debug=debug, 
                      **opts)
    

if __name__ == "__main__":
    main()        