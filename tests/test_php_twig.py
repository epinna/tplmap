import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.twig import Twig
from core.channel import Channel

class TwigTest(unittest.TestCase):

    expected_data = {
        'language': 'php',
        'engine': 'twig',
        'trailer_tag': '{{%(trailer)s}}',
        'header_tag': '{{%(header)s}}',
        'render_tag': '{{%(payload)s}}',
    }

    def test_reflection_unsecured(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15002/twig-1.24.1-secured.php?inj=*'
        })
        Twig(channel).detect()
        self.assertEqual(channel.data, self.expected_data)
