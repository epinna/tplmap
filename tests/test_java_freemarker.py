import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.freemarker import Freemarker
from core.channel import Channel

class FreemarkerTest(unittest.TestCase):


    expected_data = {
        'language': 'java',
        'engine': 'freemarker',
        'exec' : True,
        'trailer_tag': '${%(trailer)s}',
        'header_tag': '${%(header)s}',
        'render_tag': '${%(payload)s}',
    }

    def test_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15003/freemarker?inj=*'
        })
        Freemarker(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)


    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15003/freemarker?inj=*'
        })
        Freemarker(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
