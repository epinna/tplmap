import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel
from utils import rand
from utils import strings
from basetest import BaseTest

class MakoTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'eval' : 'python' ,
        'exec' : True,
        'read': True,
        'write': True,
        'trailer_tag': '${%(trailer)s}',
        'header_tag': '${%(header)s}',
        'render_tag': '${%(payload)s}',
    }
    
    url = 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*'
    plugin = Mako
    
    reflection_tests = [
        ('%s', {}),
        ('AAA%sAAA', {}),
        ('${%s}', { 'prefix' : '}', 'suffix' : '${' })
    ]
        
    def test_reflection_limit(self):
        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/limit/mako?tpl=%s&inj=*&limit=6' % template
        })

        Mako(channel).detect()

        expected_data = { 'render_tag' : self.expected_data['render_tag'] }
        
        self.assertEqual(channel.data, expected_data)