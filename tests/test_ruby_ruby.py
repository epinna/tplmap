import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.languages.ruby import Ruby
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest


class RubyTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'ruby',
        'engine': 'ruby',
        'evaluate' : 'ruby' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': '"#{%(code)s}"',
        'header': """'%(header)s'+""",
        'trailer': """+'%(trailer)s'""",
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'ruby',
        'engine': 'ruby',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'ruby',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://localhost:15005/reflect/eval?inj=*&tpl=%s'
    url_blind = 'http://localhost:15005/blind/eval?inj=*&tpl=%s'
    plugin = Ruby

    blind_tests = [
        (0, 0, '%s', {}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
    ]
    