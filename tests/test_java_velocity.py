import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.velocity import Velocity
from basetest import BaseTest

class VelocityTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'java',
        'engine': 'velocity',
        'trailer_tag': '\n#set($t=%(trailer)s)\n${t}',
        'header_tag': '\n#set($h=%(header)s)\n${h}\n',
        'render_tag': '#set($p=%(payload)s)\n${p}\n',
    }

    url = 'http://127.0.0.1:15003/velocity?inj=*&tpl=%s'

    plugin = Velocity

    reflection_tests = [
        (1, 1, '%s', {}),
        (1, 1, 'AAA%sAAA', {}),
        (1, 1, '#set( $a = "%s" )', { 'prefix' : '1")', 'suffix': ''}),
        (1, 1, '#if(1 == %s)\n#end', { 'prefix' : '1)', 'suffix': ''}),
        (3, 1, '#if(%s == 1)\n#end', { 'prefix' : '1)#end#if(1==1)', 'suffix': ''}),
        (3, 1, '#foreach($item in %s)\n#end', { 'prefix' : '1)#end#if(1==1)', 'suffix': ''}),
        (1, 1, '## comment %s', { }),
        (5, 1, '#* %s *#', { }),
        (5, 1, '#[[%s]]# ', { }),        
        (1, 1, '${%s}', {}),
        (1, 1, '${(%s)}', {}),
        (3, 1, '#define( %s )a#end', { 'prefix': '1)#end#if(1==1)', 'suffix' : ''}),
        (3, 1, '#define( $asd )%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
        (3, 1, '#macro(d)%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
    ]

    def test_download(self):
        pass

    def test_upload(self):
        pass
