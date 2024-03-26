import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.slim import Slim
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest


class SlimTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'ruby',
        'engine': 'slim',
        'evaluate' : 'ruby' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': '"#{%(code)s}"',
        'header': """=('%(header)s'+""",
        'trailer': """+'%(trailer)s')""",
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'ruby',
        'engine': 'slim',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'ruby',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://localhost:15005/reflect/slim?inj=*&tpl=%s'
    url_blind = 'http://localhost:15005/blind/slim?inj=*&tpl=%s'
    plugin = Slim
    
    #TODO: write context escape tests
    blind_tests = [
        (0, 0, '%s', {}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
    ]
    