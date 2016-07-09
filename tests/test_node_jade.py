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
        'read' : True,
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
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    
    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15004/jade?inj=*'
        })
        Jade(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        
    def test_file_read(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15004/jade?inj=*'
        })
        jadeobj = Jade(channel)
        jadeobj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        # Normal ASCII file
        readable_file = '/etc/resolv.conf'
        content = open(readable_file, 'r').read()
        self.assertEqual(content, jadeobj.read(readable_file))
        
        # Long binary file
        readable_file = '/bin/ls'
        content = open(readable_file, 'rb').read()
        self.assertEqual(content, jadeobj.read(readable_file))    
        
        # Non existant file
        self.assertEqual(None, jadeobj.read('/nonexistant'))
        # Unpermitted file
        self.assertEqual(None, jadeobj.read('/etc/shadow'))
        # Empty file
        self.assertEqual('', jadeobj.read('/dev/null'))

