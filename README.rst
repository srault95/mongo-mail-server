=================
Mongo Mail Server
=================

**Gevent SMTP Server based on** Gsmtpd_

|Build Status| |pypi downloads| |pypi dev_status| |pypi version| |pypi licence| |pypi py_versions|

**Features:**

- SMTP Server high performance with Gevent Coroutine_
- Postfix XFORWARD_ extension
- Record messages in MongoDB_
- Ability to use a custom python plugin to edit the message before recording

**The use in production is not yet guaranteed**

.. contents:: **Table of Contents**
    :depth: 1
    :backlinks: none

Quarantine mode example
=======================

**Mode for quarantine or statistics only**

.. image:: https://raw.githubusercontent.com/srault95/mongo-mail-server/master/mongo-mail-quarantine.jpg
   :alt: Mongo Mail Quarantine schema
   :align: center

- Network: smtp sender or recipient (with internet or local network)
- Content Filter: amavisd-new with xxx_quarantine_to (smtp:) parameters
- Configuration in amavisd.conf
- Zero configuration for Postfix

Proxy mode example
==================

**Mode for statistics or honey pot**

.. image:: https://raw.githubusercontent.com/srault95/mongo-mail-server/master/mongo-mail-proxy.jpg
   :alt: Mongo Mail Proxy schema
   :align: center
   
- Network: smtp sender or recipient (with internet or local network) 
- Optional: filtering after delivery to postfix by mongo mail

Filter mode example
===================

**Mode for spam/virus filtering and statistics**

.. image:: https://raw.githubusercontent.com/srault95/mongo-mail-server/master/mongo-mail-filter.jpg
   :alt: Mongo Mail Filter schema
   :align: center
   
- Network: smtp sender or recipient (with internet or local network) 
- Filtering: clamav/spamassassin with TCP connection (without amavisd-new)
- Out filter: delivered so clean else

Important Notes
===============

- **Message is not transformed (unless in quarantine mode if MMS_REAL_RCPT=1)**

- **Gross message is stored in GridFS after being compressed (zlib) and converted to base64**

- **In proxy mode, the raw message is sent before the registration in MongoDB and is not saved if an error occurs while sending or all recipients are rejected** 

Tested With
-----------

- Docker_ 1.4.1
- Ubuntu_ 14.04
- MongoDB_ 2.6.5
- Python_ 2.7.6
- Gevent_ 1.0
- Pymongo2_8 2.8 and Pymongo_ 3.0 
- Postfix_ 2.5.5
- Amavisd-new_ 2.6.4

Message Data
============

Before sent to MongoDB
----------------------

.. code:: python

    {'client_address': '139.129.236.68',
     'message': ObjectId('55252ae62d4b25262070a176'),
     'rcpt': ['jean91@example.com'],
     'rcpt_count': 1,
     'rcpt_refused': {},
     'received': datetime.datetime(2015, 4, 8, 13, 19, 34, 579000, tzinfo=tzutc()),
     'sender': 'acollet@example.org',
     'server': '127.0.0.1',
     'store_key': '77bd8b356cf2c593e61a6c0a7cbc5572eb357a7b857adca402ee40021db34fa6',
     'xforward': {'ADDR': '139.129.236.68',
                  'HELO': 'mx.example.org',
                  'NAME': 'mx.example.org'}}   
                  
    'message': ObjectId('55252ae62d4b25262070a176') is reference to data in Gridfs                                 
                      
After record in MongoDB - Read from mongo-mail-web
--------------------------------------------------

.. code:: python

    {'_id': ObjectId('55252ae62d4b25262070a178'),
     'client_address': u'139.129.236.68',
     'completed': 0,
     'errors_count': 0,
     'events': [],
     'files': [],
     'files_count': 0,
     'group_name': u'DEFAULT',
     'headers': {},
     'internal_field': 0,
     'is_banned': 0,
     'is_bounce': 0,
     'is_in': 1,
     'is_spam': 0,
     'is_unchecked': 0,
     'is_virus': 0,
     'mark_for_delete': 0,
     'message': ObjectId('55252ae62d4b25262070a176'),
     'parsing_errors': [],
     'queue': 1,
     'rcpt': [u'jean91@example.com'],
     'rcpt_count': 1,
     'rcpt_refused': {},
     'received': datetime.datetime(2015, 4, 8, 13, 19, 34, 579000, tzinfo=<bson.tz_util.FixedOffset object at 0x02B54E10>),
     'sender': u'acollet@example.org',
     'server': u'127.0.0.1',
     'size': 0L,
     'store_key': u'77bd8b356cf2c593e61a6c0a7cbc5572eb357a7b857adca402ee40021db34fa6',
     'tags': [],
     'xforward': {u'ADDR': u'139.129.236.68',
      u'HELO': u'mx.example.org',
      u'NAME': u'mx.example.org'}}

After parsing with mongo-mail-web (completed task)
--------------------------------------------------

.. code:: python

    {'_id': ObjectId('55252ae62d4b25262070a178'),
     'client_address': u'139.129.236.68',
     'completed': 1,
     'country': u'CN',
     'errors_count': 0,
     'events': [],
     'files': [],
     'files_count': 0,
     'group_name': u'DEFAULT',
     'headers': {u'Content-Transfer-Encoding': [u'base64', {}],
      u'Content-Type': [u'text/plain', {u'charset': u'utf-8'}],
      u'Date': u'Wed, 08 Apr 2015 13:19:34 UTC',
      u'From': u'"Bertrand Auger" <acollet@example.org>',
      u'Message-Id': u'<20150408131934.10264.63423@admin-VAIO>',
      u'Mime-Version': u'1.0',
      u'Subject': u'Provident tempora ad quasi enim in ratione excepturi. Optio soluta culpa voluptas labore in. Voluptatem aliquid est rerum in est adipisci dolore.',
      u'To': u'"Thierry Leleu" <jean91@example.com>',
      u'X-Mailer': u'MessageFaker'},
     'internal_field': 0,
     'is_banned': 0,
     'is_bounce': 0,
     'is_in': 1,
     'is_spam': 0,
     'is_unchecked': 0,
     'is_virus': 0,
     'mark_for_delete': 0,
     'message': ObjectId('55252ae62d4b25262070a176'),
     'message_id': u'20150408131934.10264.63423@admin-VAIO',
     'parsing_errors': [],
     'queue': 1,
     'rcpt': [u'jean91@example.com'],
     'rcpt_count': 1,
     'rcpt_refused': {},
     'received': datetime.datetime(2015, 4, 8, 13, 19, 34, 579000, tzinfo=<bson.tz_util.FixedOffset object at 0x02AC4E10>),
     'sender': u'acollet@example.org',
     'sent': datetime.datetime(2015, 4, 8, 13, 19, 34, tzinfo=<bson.tz_util.FixedOffset object at 0x02AC4E10>),
     'server': u'127.0.0.1',
     'size': 636L,
     'store_key': u'77bd8b356cf2c593e61a6c0a7cbc5572eb357a7b857adca402ee40021db34fa6',
     'subject': u'Provident tempora ad quasi enim in ratione excepturi. Optio soluta culpa voluptas labore in. Voluptatem aliquid est rerum in est adipisci dolore.',
     'tags': [],
     'xforward': {u'ADDR': u'139.129.236.68',
      u'HELO': u'mx.example.org',
      u'NAME': u'mx.example.org'}}    

Original Message
----------------

::

    Content-Type: text/plain; charset="utf-8"
    MIME-Version: 1.0
    Content-Transfer-Encoding: base64
    X-Mailer: MessageFaker
    Message-ID: <20150408131934.10264.63423@admin-VAIO>
    From: "Bertrand Auger" <acollet@example.org>
    To: "Thierry Leleu" <jean91@example.com>
    Subject: Provident tempora ad quasi enim in ratione excepturi. Optio soluta
     culpa voluptas labore in. Voluptatem aliquid est rerum in est adipisci
     dolore.
    Date: Wed, 08 Apr 2015 13:19:34 UTC
    
    U2l0IHZvbHVwdGF0ZSByZXJ1bSBjb3Jwb3JpcyBkb2xvcmlidXMgZW9zLiBRdWFzIGVvcyBub24g
    bW9kaSBxdWlzLiBBbGlhcyB2ZWwgbGF1ZGFudGl1bSBtYWduaSBzdXNjaXBpdC4gRnVnaWF0IGV0
    IHF1aXMgZXQgaW4gYWNjdXNhbXVzLg==

Environment Configuration
=========================

MMS_SERVER
----------

Server mode: mongo-quarantine | mongo-proxy | mongo-proxy | debug

Default: mongo-quarantine

.. code:: bash

    # with command mode
    $ export MMS_SERVER=mongo-quarantine
    
    # with docker environ
    $ docker run -e MMS_SERVER=mongo-quarantine
    
    # with command arguments
    $ mongo-mail-server --server mongo-quarantine 

MMS_HOST
--------

**Host bind**

*Default*: 0.0.0.0

.. code:: bash

    # with command mode
    $ export MMS_HOST=0.0.0.0
    
    # with docker environ
    $ docker run -e MMS_HOST=0.0.0.0
    
    # with command arguments
    $ mongo-mail-server --host 0.0.0.0 

MMS_PORT
--------

**Port bind**

*Default*: 14001

.. code:: bash

    # with command mode
    $ export MMS_PORT=14001
    
    # with docker environ
    $ docker run -e MMS_PORT=14001
    
    # with command arguments
    $ mongo-mail-server --port 14001
    
MMS_MONGODB_URI
---------------

*Default*: mongodb://localhost/message

http://docs.mongodb.org/manual/reference/connection-string/

.. code:: bash

    # with command mode
    $ export MMS_MONGODB_URI=mongodb://localhost/message
    
    # with docker environ
    $ docker run -e MMS_MONGODB_URI=mongodb://localhost/message
    
    # with command arguments
    $ mongo-mail-server --mongo-host mongodb://localhost/message


MMS_MONGODB_DATABASE
--------------------

**DB Name for recording mails**

*Default*: message

.. code:: bash

    # with command mode
    $ export MMS_MONGODB_DATABASE=message
    
    # with docker environ
    $ docker run -e MMS_MONGODB_DATABASE=message
    
    # with command arguments
    $ mongo-mail-server --mongo-database message



MMS_MONGODB_COLLECTION
----------------------

**Collection Name for recording mails**

*Default*: message

.. code:: bash

    # with command mode
    $ export MMS_MONGODB_COLLECTION=message
    
    # with docker environ
    $ docker run -e MMS_MONGODB_COLLECTION=message
    
    # with command arguments
    $ mongo-mail-server --mongo-collection message
     
MMS_TIMEOUT
-----------

**Timeout for smtp transaction from Postfix**

*Default: 600 (seconds)*

MMS_DATA_SIZE_LIMIT
-------------------

**Size limit of message (in bytes)**

*Default: 0 (no limit)*


Installation
============

Without Docker
--------------

Required
::::::::

- MongoDB Server
- Python 2.7.6+ (< 3.x)
- python-gevent 1.0+
- recent setuptools and pip installer

Installation
::::::::::::

.. code:: bash

    $ pip install mongo-mail-server

    $ mongo-mail-server --help 


With Docker
-----------

Required
::::::::

- Docker 1.4+
- MongoDB Server
    
MongoDB Server example
::::::::::::::::::::::

Contenair based on Ubuntu 14.04 - Python 2.7

Image from Dockerfile_

.. code:: bash

    $ docker pull dockerfile/mongodb
    
    $ docker run -d -p 27017:27017 --name mongodb dockerfile/mongodb mongod --smallfiles
    
    # Persist mongodb
    $ docker run -v /home/persist/mongodb:/data/db -d -p 27017:27017 --name mongodb dockerfile/mongodb mongod --smallfiles

Build Mongo Mail Server image
:::::::::::::::::::::::::::::

.. code:: bash

    $ git clone https://github.com/srault95/mongo-mail-server
    
    $ cd mongo-mail-server && docker build -t mongo-mail-server .
    
    # help and verify
    $ docker run -it --rm mongo-mail-server --help

Run Mongo Mail Server
:::::::::::::::::::::

.. code:: bash

    $ mongodb_ip=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' mongodb)

    # start for test
    $ docker run -it --rm -e MMS_MONGODB_URI=mongodb://$mongodb_ip/message -p 172.17.42.1:14001:14001 mongo-mail-server

    # start of background (optional: bind of docker0 interface)
    # Add --restart=always for automatic restart 
    $ docker run -d --name mms -e MMS_MONGODB_URI=mongodb://$mongodb_ip/message -p 172.17.42.1:14001:14001 mongo-mail-server

    # Logs
    $ docker logs mms
    2015-02-12 07:35:36 rs_smtpd_server: [INFO] - Starting SMTP Server - server[mongo-quarantine] - on 0.0.0.0:14001 (PID:1)
    
Usecase - Quarantine Mode configuration - with Amavis
=====================================================

**caution**

::

    Before amavisd-new 2.7.0 the recipient envelope is replaced by xxx_quarantine_to parameters
    
    Starting from 2.7.0, use macro '%a' in xxx_quarantine_to parameters

**caution**

::
    
    About IP Address of smtp sender:
    
    Amavis does not use the extension SMTPD FORWARD to send mails in quarantine. The original IP address is lost.
    
    The solution might be to use postfix to amavis output for quarantine and postfix then return the message to mongo-mail       
    

For Archiving only
------------------

.. code:: bash

    $ vi amavisd.conf
    
    # ip address and port of Mongo Mail Server
    $archive_quarantine_method      = 'smtp:[172.17.42.1]:14001';
    
    # Any valid email address. Domain few not exist
    $archive_quarantine_to          = 'archive-quarantine@localhost.net';
    
    # reload amavis

For Quarantine and Archiving
----------------------------

.. code:: bash

    $ vi amavisd.conf

    $archive_quarantine_method      = 'smtp:[172.17.42.1]:14001';
    $archive_quarantine_to          = 'archive-quarantine@localhost.net';

    $virus_quarantine_method        = $archive_quarantine_method;
    $banned_files_quarantine_method = $archive_quarantine_method;
    $spam_quarantine_method         = $archive_quarantine_method;
    
    # Not quarantine for clean mail - already stored with archive_quarantine_method
    $clean_quarantine_method        = undef;
    
    # Not quarantine for bad header mail
    $bad_header_quarantine_method   = undef;

    $virus_quarantine_to            = $archive_quarantine_to;
    $banned_quarantine_to           = $archive_quarantine_to;
    $spam_quarantine_to             = $archive_quarantine_to;
    
    #OR
    $virus_quarantine_to            = 'virus-quarantine@localhost.net';
    $banned_quarantine_to           = 'banned-quarantine@localhost.net';
    $spam_quarantine_to             = 'spam-quarantine@localhost.net';
    
Usecase - Proxy Mode - Honey pot
================================

**Dedicate a postfix server for this purpose**

.. code:: bash

    # main.cf - ip:port of Mongo Mail
    smtpd_proxy_filter=127.0.0.1:14001
    
    # or with command line
    $ postconf -e 'smtpd_proxy_filter=127.0.0.1:14001'
    
    # reload postfix
    $ postix reload
    

Using a plugin
==============

**The module must be in a package**

.. code:: python

    # just required apply(metadata=None, data=None) method

    # examples/plugins/dummy_plugin.py - modify server field and print message
    
    import pprint
    def apply(metadata=None, data=None):
        metadata['server'] = "1.1.1.1"
        pprint.pprint(metadata)    
    
    # Use:
    $ mongo-mail-server --server debug --host 127.0.0.1 --port 14001 --plugin contrib.dummy_plugin start

    # Use multiple plugins - run in the order of arguments
    $ mongo-mail-server --server --plugin myplugin1 --plugin myplugin2 ...
    
SMTP Tests - With Telnet
========================

.. code:: bash

    # Use 172.17.42.1 is binding of docker0 else:
    $ mms_ip=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' mms)

    $ telnet $mms_ip 14001
    
    Trying 172.17.1.19...
    Connected to 172.17.1.19.
    Escape character is '^]'.
    220 a88632d9a311 SMTPD at your service
    
    ehlo me.com
    250-a88632d9a311 on plain
    250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT
    250 HELP
    
    XFORWARD NAME=mail.test.fr ADDR=1.1.1.1 HELO=test.fr
    250 Ok
    
    MAIL FROM:<contact@test.fr>
    250 Ok
    
    RCPT TO:<contact@localhost.net>
    250 Ok
    
    DATA
    354 End data with <CR><LF>.<CR><LF>
    Subject: Test
    From: contact@test.fr
    To: contact@localhost.net
    
    mytest
    .
    250 Ok: queued as ab80249748e0496b812b13c489a88002fbe102fc9c263b02a8b52101491f0128
    
    QUIT
    221 Bye
    Connection closed by foreign host.
    
Use mongofiles command
======================

.. code:: bash

    $ mongofiles -d message list
    72c0f4898db56d5e10037e3f7f0c2af68704c8b86a2405d98a3e44e89bb56481        2188
    571329a72c31a914251fd6fdecb160403345ee143c194cfc442ab5bee6118918        2188
    a8de0206f9978346326cbcc9ffd5df647728268c19e8564dd1c2790b6c1404f3        2192
    ...    
    
    # Extract and write message to disk
    $ mongofiles -d message get 75e3896c1c5d98a21fc14e9408e1b9be91ced60f2bc224416de63c975c9c2915
    
    # Convert with python
    python -c "import zlib,base64; print(str(zlib.decompress(base64.b64decode(open('75e3896c1c5d98a21fc14e9408e1b9be91ced60f2bc224416de63c975c9c2915', 'rb').read()))))"

    # Parse to email.Message and print as_string()
    python -c "import zlib,base64,email; print(email.message_from_string(str(zlib.decompress(base64.b64decode(open('75e3896c1c5d98a21fc14e9408e1b9be91ced60f2bc224416de63c975c9c2915', 'rb').read())))).as_string())"
        
    
Tips
====

SMTP timeout
------------

Use MMS_TIMEOUT  in environment or --timeout

Size of messages
----------------

Use MMS_DATA_SIZE_LIMIT in environment or --data-size-limit

Open Message with Python
------------------------

.. code:: python

    >>> import os, zlib, base64
    >>> from pprint import pprint as pp
    >>> from email.parser import Parser, HeaderParser
    >>> from pymongo import MongoClient
    >>> from gridfs import GridFS
    >>> client = MongoClient(os.environ.get('MMS_MONGODB_URI'))
    >>> db = client['message']
    >>> col = db['message']
    >>> doc = col.find_one() 
    >>> fs = GridFS(db)
    >>> msg_base64 = fs.get(doc['message']).read()
    >>> msg_string = zlib.decompress(base64.b64decode(msg_base64))
    >>> msg = Parser().parsestr(msg_string)
    >>> msg
    <email.message.Message instance at 0x7ff5e4054560>    


TODO
====

- More tests
- Travis tests
- Monitoring with psutil
- Filter tasks
- Documentation of mongo-mail-reader command
- Documentation en Français

Ideas
=====

- Record to ElasticSearch
- Sends statistics to graphite, statsd, influxdb

**Welcome to all contributors**

.. _Gsmtpd: https://github.com/34nm/gsmtpd
.. _MongoDB: http://mongodb.org/
.. _Docker: https://www.docker.com/
.. _Ubuntu: http://www.ubuntu.com/
.. _Dockerfile: http://dockerfile.github.io/#/mongodb
.. _Python: http://www.python.org/
.. _Pymongo2_8: http://api.mongodb.org/python/2.8/
.. _Pymongo: http://api.mongodb.org/python/current/index.html
.. _Gevent: http://www.gevent.org/
.. _Postfix: http://www.postfix.org
.. _XFORWARD: http://www.postfix.org/XFORWARD_README.html
.. _Amavisd-new: http://www.ijs.si/software/amavisd/
.. _Clamav: http://clamav.net/
.. _SpamAssassin: http://spamassassin.org/
.. _Coroutine: http://en.wikipedia.org/wiki/Coroutine
 
.. |Build Status| image:: https://travis-ci.org/srault95/mongo-mail-server.svg?branch=master
   :target: https://travis-ci.org/srault95/mongo-mail-server
   :alt: Travis Build Status

.. |pypi downloads| image:: https://pypip.in/download/mongo-mail-server/badge.svg
    :target: https://pypi.python.org/pypi/mongo-mail-server
    :alt: Number of PyPI downloads
    
.. |pypi version| image:: https://pypip.in/version/mongo-mail-server/badge.svg
    :target: https://pypi.python.org/pypi/mongo-mail-server
    :alt: Latest Version    

.. |pypi licence| image:: https://pypip.in/license/mongo-mail-server/badge.svg
    :target: https://pypi.python.org/pypi/mongo-mail-server
    :alt: License

.. |pypi py_versions| image:: https://pypip.in/py_versions/mongo-mail-server/badge.svg
    :target: https://pypi.python.org/pypi/mongo-mail-server
    :alt: Supported Python versions

.. |pypi dev_status| image:: https://pypip.in/status/mongo-mail-server/badge.svg
    :target: https://pypi.python.org/pypi/mongo-mail-server
    :alt: Development Status        
    