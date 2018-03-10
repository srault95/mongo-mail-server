# -*- coding: utf-8 -*-

from contextlib import contextmanager
import os
import smtplib
from email.utils import getaddresses

import gevent
import pymongo

from mongo_mail_server import RecordPyMongoDBServer, compress, uncompress, PYMONGO2

from . import utils

MSG1 = """X-Envelope-From: <sender@example.org>
X-Envelope-To: <recipient@example.net>
From: root (Cron Daemon)
To: <recipient@example.net>
Subject: Test1
Content-Type: text/plain; charset=ASCII
Message-Id: <20150209054755.A04D818B6@localhost>
Date: Mon,  9 Feb 2015 05:47:55 +0000 (UTC)

My message
"""


MSG_RCPT_NOT_FQDN = """X-Envelope-From: root
X-Envelope-To: root
From: root (Cron Daemon)
To: clamav
Subject: Test not fqdn
Content-Type: text/plain; charset=ASCII
Message-Id: <20150209054755.A04D818B6@localhost>
Date: Mon,  9 Feb 2015 05:47:55 +0000 (UTC)

My message
"""

MSG_QUARANTINE_REAL_RCPT = """X-Envelope-From: <sender@example.org>
X-Envelope-To: <real-rcpt@example.net>
From: root (Cron Daemon)
To: clamav
Subject: Test real rcpt
Content-Type: text/plain; charset=ASCII
Message-Id: <20150209054755.A04D818B6@localhost>
Date: Mon,  9 Feb 2015 05:47:55 +0000 (UTC)

My message
"""

MSG_QUARANTINE_REAL_RCPT_MULTI = """X-Envelope-From: <sender@example.org>
X-Envelope-To: <real-rcpt1@example.net>,
        <real-rcpt2@example.net>
From: root (Cron Daemon)
To: <real-rcpt1@example.net>,
        <real-rcpt2@example.net>
Subject: Test multi recipients
Content-Type: text/plain; charset=ASCII
Message-Id: <20150209054755.A04D818B6@localhost>
Date: Mon,  9 Feb 2015 05:47:55 +0000 (UTC)

My message
"""

DB_NAME = "message_test"

COL_NAME = "message_test"

MONGODB_SETTINGS = {
    'host': os.environ.get('MMS_MONGODB_URI', 'mongodb://localhost'),
    'tz_aware': True,
}
if PYMONGO2:
    MONGODB_SETTINGS['use_greenlets'] = True

@contextmanager
def smtp_server(host=None, port=None, mongo_settings=None, timeout=10, data_size_limit=0, **kwargs):

    from pymongo import MongoClient

    client = MongoClient(**mongo_settings)

    server = RecordPyMongoDBServer(localaddr=(host, port),
                                 timeout=timeout,
                                 data_size_limit=data_size_limit,
                                 db=client[DB_NAME],
                                 colname=COL_NAME,
                                 **kwargs)

    server.db.drop_collection(COL_NAME)
    server.db.drop_collection('fs.files')
    server.db.drop_collection('fs.chunks')

    try:
        gevent.spawn(server.start)
        gevent.sleep(0)
        yield server
    finally:
        server.stop()

def smtp_client(host=None, port=None, debug=False):
    smtp = smtplib.SMTP(host=host, port=port)
    if debug:
        smtp.set_debuglevel(1)
    smtp.does_esmtp = 1
    return smtp

def _sendmail(message=None, debug=False, timeout=10, mongo_settings=None, sleeping=None, smtp_rcpt=None, **kwargs):

    host, port = utils.get_free_port()

    with smtp_server(host=host, port=port, mongo_settings=mongo_settings, timeout=timeout, **kwargs) as server:

        assert server.col.count() == 0

        s = smtp_client(host, port, debug=debug)

        (code, msg) = s.ehlo()
        assert code == 250

        if sleeping:
            gevent.sleep(sleeping)

        xforward = {
            'ADDR': '192.168.1.1',
            'NAME': 'mail.local.net',
            'HELO': 'local.net',
        }
        (code, msg) = s.docmd('XFORWARD', 'ADDR=%(ADDR)s NAME=%(NAME)s HELO=%(HELO)s' % xforward)
        assert code == 250

        froms = message.get_all('X-Envelope-From', [])

        if not smtp_rcpt:
            _recipients = message.get_all('X-Envelope-To', [])
            recipients = getaddresses(_recipients)
        else:
            recipients = [smtp_rcpt]

        message_string = message.as_string()

        (code, msg) = s.mail(smtplib.quoteaddr(froms[0]), ["size=%s" % len(message_string)])

        assert code == 250

        for recipient in recipients:
            (code, msg) = s.docmd('RCPT TO:', smtplib.quoteaddr(recipient) )
            assert code == 250

        (code, msg) = s.data(message_string)
        assert code == 250

        (code, msg) = s.docmd('quit')
        assert code == 221

        return server

def _mongodb_verify(message=None, col=None, fs=None, debug=False):

    froms = message.get_all('X-Envelope-From', [])

    doc = col.find_one()

    assert doc['sender'] == smtplib.quoteaddr(froms[0])[1:-1]

    msg = utils.message_from_string(uncompress(fs.get(doc['message']).read()))

    if debug:
        print ""
        print "------------------------------------------------------------"
        print message.as_string()
        print "------------------------------------------------------------"

    return doc, msg

def test_send():

    message = utils.message_from_string(MSG1)
    server = _sendmail(message=message, mongo_settings=MONGODB_SETTINGS ,debug=False)
    assert server.col.count() == 1
    doc, new_message = _mongodb_verify(message=message, col=server.col, fs=server.fs, debug=False)

def test_send_rcpt_not_fqdn():
    u"""Not fqdn sender and recipient"""

    message = utils.message_from_string(MSG_RCPT_NOT_FQDN)
    server = _sendmail(message=message, mongo_settings=MONGODB_SETTINGS ,debug=False)
    assert server.col.count() == 1
    doc, new_message = _mongodb_verify(message=message, col=server.col, fs=server.fs, debug=False)
    assert len(doc['rcpt']) == 1
    assert doc['rcpt'][0] == 'root'

def test_send_convert_real_rcpt():
    u"""Replace smtp rcpttos with X-Envelope-To field"""

    message = utils.message_from_string(MSG_QUARANTINE_REAL_RCPT)
    server = _sendmail(message=message, mongo_settings=MONGODB_SETTINGS ,debug=False, smtp_rcpt='quarantine@localhost.net', real_rcpt=True)
    assert server.col.count() == 1
    doc, new_message = _mongodb_verify(message=message, col=server.col, fs=server.fs, debug=False)
    assert len(doc['rcpt']) == 1
    assert doc['rcpt'][0] == 'real-rcpt@example.net'
    header_mms_rcpt = new_message.get('X-MMS-RCPT', None)
    assert not header_mms_rcpt is None
    assert header_mms_rcpt == "<quarantine@localhost.net>"

def test_send_convert_real_rcpt_multi():
    u"""Replace smtp rcpttos with X-Envelope-To field - multi real rcpt"""

    message = utils.message_from_string(MSG_QUARANTINE_REAL_RCPT_MULTI)
    server = _sendmail(message=message, mongo_settings=MONGODB_SETTINGS ,debug=False, smtp_rcpt='quarantine@localhost.net', real_rcpt=True)
    assert server.col.count() == 1
    doc, new_message = _mongodb_verify(message=message, col=server.col, fs=server.fs, debug=False)
    assert len(doc['rcpt']) == 2
    assert doc['rcpt'][0] == 'real-rcpt1@example.net'
    header_mms_rcpt = new_message.get('X-MMS-RCPT', None)
    assert not header_mms_rcpt is None
    assert header_mms_rcpt == "<quarantine@localhost.net>"

def test_send_with_timeout():

    try:
        _sendmail(sleeping=1.2, timeout=2, mongo_settings=MONGODB_SETTINGS)
    except smtplib.SMTPServerDisconnected:
        pass
    except Exception, err:
        pass
    else:
        assert False, "Exception not raised"

def test_implemented_commands():

    host, port = utils.get_free_port()

    with smtp_server(host=host, port=port,
                     mongo_settings=MONGODB_SETTINGS,
                     data_size_limit=100) as server:

        s = smtp_client(host, port, debug=False)

        (code, msg) = s.ehlo()

        for feature in ["xforward", "size", "help"]:
            assert feature in s.esmtp_features

#def test_limit_size():
#    assert False, "Not Implemented"



