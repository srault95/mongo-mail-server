# -*- coding: utf-8 -*-

import pprint

def apply(metadata=None, data=None):
    metadata['server'] = "1.1.1.1"
    pprint.pprint(metadata)