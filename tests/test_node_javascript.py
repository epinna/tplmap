import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.languages.javascript import Javascript
from basetest import BaseTest


class JavascriptTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'javascript',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': """%(code)s""",
        'header': """'%(header)s'+""",
        'trailer': """+'%(trailer)s'""",
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'javascript',
        'blind': True,
        'execute_blind' : True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/javascript?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/javascript?inj=*&tpl=%s'
    plugin = Javascript


    blind_tests = [
        (0, 0, '%s', {}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (2, 0, 'if("%s"=="2"){}', { 'prefix' : '1")', 'suffix' : '//'}),
        (1, 3, '["%s"]', { 'prefix': '1"];', 'suffix' : '//' }),
        
        # Comment blocks
        # TODO: Can't be tested since * is considered as placeholder. Fix this.
        #(5, 0, '/%2A%s%2A/', { 'prefix' : '*/', 'suffix' : '//'}),

    ]
    