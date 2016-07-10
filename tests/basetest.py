import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from core.channel import Channel
from utils import rand
from utils import strings

class BaseTest(object):
    
    def _get_detection_obj_data(self, url):
        
        channel = Channel({
            'url' : url
        })
        obj = self.plugin(channel)
        obj.detect()
        
        # Delete OS to make the tests portable
        if 'os' in channel.data:
            del channel.data['os']
            
        return obj, channel.data
        
    def test_reflection(self):
        
        for reflection_test in self.reflection_tests:
            
            risk, template, channel_updates = reflection_test

            expected_data = self.expected_data.copy()
            expected_data.update(channel_updates)
            
            obj, data = self._get_detection_obj_data(self.url % template)
            
            # Set the required risk level
            obj.channel.args['level'] = risk
            
            self.assertEqual(
                data, 
                expected_data, 
            )

    def test_download(self):

        obj, data = self._get_detection_obj_data(self.url % '')
        self.assertEqual(data, self.expected_data)
        
        # Normal ASCII file
        readable_file = '/etc/resolv.conf'
        content = open(readable_file, 'r').read()
        self.assertEqual(content, obj.read(readable_file))
        
        # Long binary file
        readable_file = '/bin/ls'
        content = open(readable_file, 'rb').read()
        self.assertEqual(content, obj.read(readable_file))    
        
        # Non existant file
        self.assertEqual(None, obj.read('/nonexistant'))
        # Unpermitted file
        self.assertEqual(None, obj.read('/etc/shadow'))
        # Empty file
        self.assertEqual('', obj.read('/dev/null'))

    def test_upload(self):

        obj, data = self._get_detection_obj_data(self.url % '')
        self.assertEqual(data, self.expected_data)

        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        
        # Send long binary
        data = open('/bin/ls', 'rb').read()
        obj.write(data, remote_temp_path)
        self.assertEqual(obj._md5(remote_temp_path), strings.md5(data))
        obj.execute('rm %s' % (remote_temp_path))
        
        # Send short ASCII data, without removing it
        data = 'SHORT ASCII DATA'
        obj.write(data, remote_temp_path)
        self.assertEqual(obj._md5(remote_temp_path), strings.md5(data))

        # Try to append data without --force-overwrite and re-check the previous md5
        obj.write('APPENDED DATA', remote_temp_path)
        self.assertEqual(obj._md5(remote_temp_path), strings.md5(data))
        
        # Now set --force-overwrite and rewrite new data on the same file
        obj.channel.args['force_overwrite'] = True
        data = 'NEW DATA'
        obj.write(data, remote_temp_path)
        self.assertEqual(obj._md5(remote_temp_path), strings.md5(data))
        obj.execute('rm %s' % (remote_temp_path))
