import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from core.channel import Channel
from core.checks import check_template_injection
from core.checks import detect_template_injection
from utils import rand
from utils import strings
import utils.loggers
import logging

utils.loggers.stream_handler.setLevel(logging.FATAL)

# Test levels limits
LEVEL_LIMIT = 0
CLEVEL_LIMIT = 0

# Extra tests
EXTRA_UPLOAD = False
EXTRA_DOWNLOAD = False
EXTRA_UPLOAD_BLIND = False

class BaseTest(object):

    def _get_detection_obj_data(self, url, level = 0, closure_level = 0, technique = 'RT'):

        channel = Channel({
            'url' : url,
            'force_level': [ level, closure_level ],
            'injection_tag': '*',
            'technique': technique
        })
        obj = detect_template_injection(channel, [ self.plugin ])

        # Delete OS to make the tests portable
        if 'os' in channel.data:
            del channel.data['os']

        return obj, channel.data


    def test_detection(self):

        channel = Channel({
            'url' : self.url,
            'level': 5,
            'injection_tag': '*',
            'technique': 'RT'
        })
        check_template_injection(channel)

        # Delete OS to make the tests portable
        if 'os' in channel.data:
            del channel.data['os']

        # Delete any unreliable engine detected
        if 'unreliable' in channel.data:
            del channel.data['unreliable']

        self.assertEqual(
            channel.data,
            self.expected_data,
        )

    def test_reflection(self):

        for reflection_test in self.reflection_tests:

            level, clevel, template, channel_updates = reflection_test

            # Honour global level limit
            if level > LEVEL_LIMIT or clevel > CLEVEL_LIMIT:
                continue

            expected_data = self.expected_data.copy()
            expected_data.update(channel_updates)

            obj, data = self._get_detection_obj_data(self.url % template, level, clevel, technique = 'R')

            self.assertEqual(
                data,
                expected_data,
                msg = '\nreflection\ntemplate: %s\nlevels: %i %i\nreturned data: %s\nexpected data: %s' % (repr(template).strip("'"), level, clevel, str(data), str(expected_data))
            )

    def test_blind(self):

        for blind_test in self.blind_tests:

            level, clevel, template, channel_updates = blind_test

            # Honour global level limit
            if level > LEVEL_LIMIT or clevel > CLEVEL_LIMIT:
                continue
                
            expected_data = self.expected_data_blind.copy()
            expected_data.update(channel_updates)

            obj, data = self._get_detection_obj_data(self.url_blind % template, level, clevel, technique = 'T')

            self.assertEqual(
                data,
                expected_data,
                msg = '\nblind\ntemplate: %s\nlevels: %i %i\nreturned data: %s\nexpected data: %s' % (repr(template).strip("'"), level, clevel, str(data), str(expected_data))
            )

    def test_download(self):

        obj, data = self._get_detection_obj_data(self.url)
        self.assertEqual(data, self.expected_data)

        if not EXTRA_DOWNLOAD:
            return

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

        obj, data = self._get_detection_obj_data(self.url)
        self.assertEqual(data, self.expected_data)
        
        if not EXTRA_UPLOAD:
            return

        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        # Send long binary
        data = open('/bin/ls', 'rb').read()
        obj.write(data, remote_temp_path)
        self.assertEqual(obj.md5(remote_temp_path), strings.md5(data))
        obj.execute('rm %s' % (remote_temp_path))

        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        # Send short ASCII data, without removing it
        data = 'SHORT ASCII DATA'
        obj.write(data, remote_temp_path)
        self.assertEqual(obj.md5(remote_temp_path), strings.md5(data))

        # Try to append data without --force-overwrite and re-check the previous md5
        obj.write('APPENDED DATA', remote_temp_path)
        self.assertEqual(obj.md5(remote_temp_path), strings.md5(data))

        # Now set --force-overwrite and rewrite new data on the same file
        obj.channel.args['force_overwrite'] = True
        data = 'NEW DATA'
        obj.write(data, remote_temp_path)
        self.assertEqual(obj.md5(remote_temp_path), strings.md5(data))
        obj.execute('rm %s' % (remote_temp_path))
            
    def test_upload_blind(self):

        obj, data = self._get_detection_obj_data(
            self.url_blind,
            technique = 'T'
        )
        self.assertEqual(data, self.expected_data_blind)

        if not EXTRA_UPLOAD_BLIND:
            return

        # Send file without --force-overwrite, should fail
        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        obj.write('AAAA', remote_temp_path)
        self.assertFalse(os.path.exists(remote_temp_path))

        # Now set --force-overwrite and retry
        obj.channel.args['force_overwrite'] = True

        # Send long binary
        data = open('/bin/ls', 'rb').read()
        obj.write(data, remote_temp_path)
        
        # Since it's blind, read md5 from disk
        checkdata = open(remote_temp_path, 'rb').read()
        self.assertEqual(strings.md5(checkdata), strings.md5(data))
        os.unlink(remote_temp_path)
        
        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        # Send short ASCII data
        data = 'SHORT ASCII DATA'
        obj.write(data, remote_temp_path)
        
        checkdata = open(remote_temp_path, 'rb').read()
        self.assertEqual(strings.md5(checkdata), strings.md5(data))
        os.unlink(remote_temp_path)    