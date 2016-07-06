import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.jade import Jade
from core.channel import Channel

class JadeTest(unittest.TestCase):

    expected_data = {
        'language': 'javascript',
        'engine': 'jade',
        'eval' : 'javascript' ,
        'exec' : True,
        'os' : 'darwin',
        'trailer_tag': '\n= %(trailer)s\n',
        'header_tag': '\n= %(header)s\n',
        'render_tag': '\n= %(payload)s\n',
    }

    def test_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15004/jade?inj=*'
        })
        Jade(channel).detect()
        self.assertEqual(channel.data, self.expected_data)

    
    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15004/jade?inj=*'
        })
        Jade(channel).detect()
        self.assertEqual(channel.data, self.expected_data)
        