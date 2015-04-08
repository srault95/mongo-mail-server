# -*- coding: utf-8 -*-

import gzip
import base64
import email
import uuid
import hashlib

from StringIO import StringIO

def get_free_port():
    u"""Récupère un port libre pour les tests et ferme la socket std"""
    import socket
    tempsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tempsock.bind(('localhost', 0))
    host, unused_port = tempsock.getsockname()
    tempsock.close()
    return host, unused_port

def decompress(filepath):
    with gzip.open(filepath) as fp:
        fileobj = StringIO(fp.read())
        return fileobj

def message_from_filepath(filepath):
    import email
    fileobj = decompress(filepath)
    return email.message_from_file(fileobj)

def message_from_string(content):
    import email
    return email.message_from_string(content)

