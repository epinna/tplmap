import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel

class MakoTest(unittest.TestCase):
    
    def test_reflection(self):
        
        template = '%s'
        
        channel = Channel('http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*' % template)
        Mako(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '${%s}',
            'language': 'python',
            'engine': 'mako',  
            'exec' : True,
            'os' : 'posix-darwin'
        })

    
    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'
        
        channel = Channel('http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*' % template)
        Mako(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '${%s}',
            'language': 'python',
            'engine': 'mako',
            'exec' : True,
            'os' : 'posix-darwin'
        })
        