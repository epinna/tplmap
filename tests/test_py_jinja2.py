import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.jinja2 import Jinja2
from core.channel import Channel

class Jinja2Test(unittest.TestCase):
    
    def test_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '{{%s}}',
            'language': 'python',
            'engine': 'jinja2',  
            'exec' : True,
            'os' : 'posix-darwin'
        })

    
    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '{{%s}}',
            'language': 'python',
            'engine': 'jinja2',
            'exec' : True,
            'os' : 'posix-darwin'
        })
        