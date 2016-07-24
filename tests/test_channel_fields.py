import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel
import utils.loggers
import logging

utils.loggers.stream_handler.setLevel(logging.FATAL)

class ChannelTest(unittest.TestCase):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'evaluate' : 'python' ,
        'execute' : True,
        'write' : True,
        'read' : True,
        'trailer': '${%(trailer)s}',
        'header': '${%(header)s}',
        'render': '${%(code)s}',
        'prefix': '',
        'suffix': ''
    }

    def test_post_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/post/mako',
            'force_level': [ 0, 0 ],
            'post_data' : [ 'inj=*' ]
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_header_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/header/mako',
            'force_level': [ 0, 0 ],
            'headers' : [ 'User-Agent: *' ]
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_put_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/put/mako',
            'post_data' : [ 'inj=*' ],
            'method' : 'PUT',
            'force_level': [ 0, 0 ],
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
