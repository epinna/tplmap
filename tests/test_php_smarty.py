import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from core.channel import Channel
from utils import rand
from utils import strings

class SmartyTest(unittest.TestCase):

    expected_data = {
        'language': 'php',
        'engine': 'smarty',
        'eval' : 'php' ,
        'exec' : True,
        'write': True,
        'read': True,
        'trailer_tag': '{%(trailer)s}',
        'header_tag': '{%(header)s}',
        'render_tag': '{%(payload)s}',
    }

    def test_reflection_unsecured(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15002/smarty-3.1.29-unsecured.php?inj=*'
        })
        Smarty(channel).detect()
        
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_reflection_secured(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15002/smarty-3.1.29-secured.php?inj=*'
        })
        Smarty(channel).detect()

        expected_data = self.expected_data.copy()
        del expected_data['eval']
        del expected_data['exec']
        
        self.assertEqual(channel.data, expected_data)

        
    def test_download(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15002/smarty-3.1.29-unsecured.php?inj=*'
        })
        smartyobj = Smarty(channel)
        smartyobj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        # Normal ASCII file
        readable_file = '/etc/resolv.conf'
        content = open(readable_file, 'r').read()
        self.assertEqual(content, smartyobj.read(readable_file))
        
        # Long binary file
        readable_file = '/bin/ls'
        content = open(readable_file, 'rb').read()
        self.assertEqual(content, smartyobj.read(readable_file))    
        
        # Non existant file
        self.assertEqual(None, smartyobj.read('/nonexistant'))
        # Unpermitted file
        self.assertEqual(None, smartyobj.read('/etc/shadow'))
        # Empty file - returns None, unlike the others
        self.assertEqual(None, smartyobj.read('/dev/null'))

    def test_upload(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15002/smarty-3.1.29-unsecured.php?inj=*'
        })
        smartyobj = Smarty(channel)
        smartyobj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        
        # Send long binary
        data = open('/bin/ls', 'rb').read()
        smartyobj.write(data, remote_temp_path)
        self.assertEqual(smartyobj._md5(remote_temp_path), strings.md5(data))
        smartyobj.execute('rm %s' % (remote_temp_path))
        
        # Send short ASCII data, without removing it
        data = 'SHORT ASCII DATA'
        smartyobj.write(data, remote_temp_path)
        self.assertEqual(smartyobj._md5(remote_temp_path), strings.md5(data))

        # Try to append data without --force-overwrite and re-check the previous md5
        smartyobj.write('APPENDED DATA', remote_temp_path)
        self.assertEqual(smartyobj._md5(remote_temp_path), strings.md5(data))
        
        # Now set --force-overwrite and rewrite new data on the same file
        smartyobj.channel.args['force_overwrite'] = True
        data = 'NEW DATA'
        smartyobj.write(data, remote_temp_path)
        self.assertEqual(smartyobj._md5(remote_temp_path), strings.md5(data))
        smartyobj.execute('rm %s' % (remote_temp_path))
