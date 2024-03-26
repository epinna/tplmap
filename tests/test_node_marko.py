import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.marko import Marko
from basetest import BaseTest


class MarkoTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'marko',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': '${%(code)s}',
        'header': '${"%(header)s"}',
        'trailer': '${"%(trailer)s"}',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'marko',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'javascript',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/marko?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/marko?inj=*&tpl=%s'
    plugin = Marko


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (1, 0, '${%s}', { 'prefix': '1}', 'suffix' : '${"1"' }),
        (2, 0, '<var name=%s/>', { 'prefix': '1/>', 'suffix' : '' }),
        (2, 0, '<assign name=%s/>', { 'prefix': '1/>', 'suffix' : '' }),
    ]