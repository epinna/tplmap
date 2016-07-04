import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from core.channel import Channel

class SmartyTest(unittest.TestCase):
    
    def test_reflection_unsecured(self):
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/smarty-3.1.29-unsecured.php?inj=*'
        })
        Smarty(channel).detect()
        self.assertEqual(channel.data, { 
            'reflect_tag': '{%s}',
            'language': 'php',
            'engine': 'smarty-unsecured',  
            'exec' : True,
            'os' : 'Darwin'
        })

    def test_reflection_secured(self):
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/smarty-3.1.29-secured.php?inj=*'
        })
        Smarty(channel).detect()
        self.assertEqual(channel.data, { 
            'reflect_tag': '{%s}',
            'language': 'php',
            'engine': 'smarty-secured'
        })