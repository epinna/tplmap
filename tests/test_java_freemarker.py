import unittest
import requests
import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.freemarker import Freemarker
from basetest import BaseTest

class FreemarkerTest(unittest.TestCase, BaseTest):


    expected_data = {
        'language': 'java',
        'engine': 'freemarker',
        'execute' : True,
        'trailer': '${%(trailer)s?c}',
        'header': '${%(header)s?c}',
        'render': '%(code)s',
        'write': True,
        'read': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'java',
        'engine': 'freemarker',
        'blind': True,
        'execute_blind' : True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15003/freemarker?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15003/freemarker?inj=*&tpl=%s&blind=1'

    plugin = Freemarker

    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (5, 5, '<#list %s as a></#list>', { 'prefix' : '[1] as a></#list><#list [1] as a>', 'suffix' : ''}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (1, 0, '${ %s }', { 'prefix': '1}', 'suffix': '' }),

        (2, 1, '<#assign s = %s>', { 'prefix': '1>', 'suffix': '' }),
        (5, 1, '<#-- %s -->', { 'prefix': '-->', 'suffix': '<#--' }),
        (2, 1, '<#if 1 == %s></#if>', { 'prefix': '1>', 'suffix' : ''}),
        (2, 2, '<#if %s == 1></#if>', { 'prefix': 'true>', 'suffix' : ''}),
        (5, 3, '<#list [%s] as a></#list>', { 'prefix' : '1] as a></#list><#list [1] as a>', 'suffix' : ''}),
        (5, 5, '<#list %s as a></#list>', { 'prefix' : '[1] as a></#list><#list [1] as a>', 'suffix' : ''}),
        (1, 5, '<#assign ages = {"J":2, "%s":2}>', { 'prefix' : '1":1}]}', 'suffix' : ''}),

        #(1, 5, '${[1,2]%3Fjoin(%s)}', { 'prefix' : '[1])}', 'suffix' : ''}),

    ]
