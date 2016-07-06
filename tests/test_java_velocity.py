import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.velocity import Velocity
from core.channel import Channel

class VelocityTest(unittest.TestCase):
    
    expected_data = {
        'language': 'java',
        'engine': 'velocity',
        'trailer_tag': '\n#set($t=%(trailer)s)\n$t',
        'header_tag': '#set($h=%(header)s)\n$h\n',
        'render_tag': '#set($p=%(payload)s)\n$p\n',
    }
    
    def test_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15003/velocity?inj=*'
        })
        Velocity(channel).detect()
        self.assertEqual(channel.data, self.expected_data)

    
    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15003/velocity?inj=*'
        })
        Velocity(channel).detect()
        self.assertEqual(channel.data, self.expected_data)
        