import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.freemarker import Freemarker
from core.channel import Channel

class FreemarkerTest(unittest.TestCase):
    
    def test_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/freemarker?inj=*'
        })
        Freemarker(channel).detect()
        self.assertEqual(channel.data, { 
            'reflect_tag': '${%s}',
            'language': 'java',
            'engine': 'freemarker',  
            'exec' : True,
            'os' : 'Darwin'
        })

    
    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/freemarker?inj=*'
        })
        Freemarker(channel).detect()
        self.assertEqual(channel.data, {
            'reflect_tag': '${%s}',
            'language': 'java',
            'engine': 'freemarker',  
            'exec' : True,
            'os' : 'Darwin'
        })
        