import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel

class ChannelTest(unittest.TestCase):
    
    def test_post_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/post/mako',
            'post_data' : [ 'inj=*' ]
        })
        Mako(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '${%s}',
            'language': 'python',
            'engine': 'mako',  
            'exec' : True,
            'os' : 'posix-darwin'
        })

    def test_header_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/header/mako',
            'headers' : [ 'User-Agent: *' ]
        })
        Mako(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '${%s}',
            'language': 'python',
            'engine': 'mako',  
            'exec' : True,
            'os' : 'posix-darwin'
        })

    def test_put_reflection(self):
        
        template = '%s'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/put/mako',
            'post_data' : [ 'inj=*' ],
            'method' : 'PUT'
        })
        Mako(channel)
        self.assertEqual(channel.data, { 
            'reflect_tag': '${%s}',
            'language': 'python',
            'engine': 'mako',  
            'exec' : True,
            'os' : 'posix-darwin'
        })