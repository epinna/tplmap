import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from core.channel import Channel

class SmartyTest(unittest.TestCase):

    expected_data = {
        'language': 'php',
        'engine': 'smarty',
        'eval' : 'php' ,
        'exec' : True,
        'os' : 'Darwin',
        'trailer_tag': '{%(trailer)s}',
        'header_tag': '{%(header)s}',
        'render_tag': '{%(payload)s}',
    }

    def test_reflection_unsecured(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/smarty-3.1.29-unsecured.php?inj=*'
        })
        Smarty(channel).detect()
        self.assertEqual(channel.data, self.expected_data)

    def test_reflection_secured(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/smarty-3.1.29-secured.php?inj=*'
        })
        Smarty(channel).detect()

        expected_data = self.expected_data.copy()
        del expected_data['eval']
        del expected_data['os']
        del expected_data['exec']

        self.assertEqual(channel.data, expected_data)
