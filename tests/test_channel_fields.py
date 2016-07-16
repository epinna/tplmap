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
        'eval' : 'python' ,
        'exec' : True,
        'write' : True,
        'read' : True,
        'trailer_fmt': '${%(trailer)s}',
        'header_fmt': '${%(header)s}',
        'render_fmt': '${%(payload)s}',
    }

    def test_post_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/post/mako',
            'post_data' : [ 'inj=*' ]
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_header_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/header/mako',
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
            'method' : 'PUT'
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
