import unittest
import requests
import os
import sys
import random

sys.path.insert(10, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel
from utils import rand
from utils import strings
from basetest import BaseTest

class MakoTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'evaluate' : 'python',
        'execute' : True,
        'read': True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'trailer': '${%(trailer)s}',
        'header': '${%(header)s}',
        'render': '${%(code)s}',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'python',
        'engine': 'mako',
        'blind': True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'evaluate_blind': 'python',
        'execute_blind': True,
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*'
    url_blind = 'http://127.0.0.1:15001/blind/mako?tpl=%s&inj=*'

    plugin = Mako

    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (1, 5, '<%% a=set(["""%s"""]) %%>', { 'prefix' : '1"""])%>', 'suffix' : '<%#' }),
    ]

    reflection_tests = [

        # Text context
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),

        # Reflecting tag ${} context
        (1, 1, '${ %s = 1 }', {  'prefix': '1}', 'suffix' : ''  }),
        (1, 1, '${%s}', { 'prefix': '1}', 'suffix' : '' }),
        (1, 1, '${ \'%s\' }', { 'prefix': '1\'}', 'suffix' : '' }),
        (1, 1, '${ "%s" }', { 'prefix': '1"}', 'suffix' : '' }),
        (1, 3, '${ """%s""" }', { 'prefix': '1"""}', 'suffix' : '' }),
        (1, 2, '${ range(%s) }', { 'prefix': '1)}', 'suffix' : '' }),
        (1, 2, '${ set(\'%s\') }', { 'prefix': '1\')}', 'suffix' : '' }),
        (1, 2, '${ set("%s") }', { 'prefix': '1")}', 'suffix' : '' }),
        (1, 3, '${ set("""%s""") }', { 'prefix': '1""")}', 'suffix' : '' }),

        (1, 3, '${[%s]}', { 'prefix': '1]}', 'suffix' : '' }),
        (1, 3, '${ [\'%s\'] }', { 'prefix': '1\']}', 'suffix' : '' }),
        (1, 3, '${ ["%s"] }', { 'prefix': '1"]}', 'suffix' : '' }),
        (1, 3, '${ ["""%s"""] }', { 'prefix': '1"""]}', 'suffix' : '' }),
        (1, 5, '${ set([%s]) }', { 'prefix': '1])}', 'suffix' : '' }),
        (1, 5, '${ set([\'%s\']) }', { 'prefix': '1\'])}', 'suffix' : '' }),
        (1, 5, '${ set(["%s"]) }', { 'prefix': '1"])}', 'suffix' : '' }),
        (1, 5, '${ set(["""%s"""]) }', { 'prefix': '1"""])}', 'suffix' : '' }),

        (1, 3, '${{%s}}', { 'prefix': '1}}', 'suffix' : '' }),
        (1, 3, '${{1:%s}}', { 'prefix': '1}}', 'suffix' : '' }),
        (1, 3, '${ {1:\'%s\'} }', { 'prefix': '1\'}}', 'suffix' : '' }),
        (1, 3, '${ {1:"%s"} }', { 'prefix': '1"}}', 'suffix' : '' }),
        (1, 3, '${ {1:"""%s"""} }', { 'prefix': '1"""}}', 'suffix' : '' }),
        (1, 3, '${{3:4, %s:1}}', { 'prefix': '1:1}}', 'suffix' : '' }),
        (1, 3, '${ {\'%s\':1} }', { 'prefix': '1\'}}', 'suffix' : '' }),
        (1, 3, '${ {"%s":1} }', { 'prefix': '1"}}', 'suffix' : '' }),
        (1, 3, '${ {"""%s""":1} }', { 'prefix': '1"""}}', 'suffix' : '' }),

        # Code blocks context
        (1, 1, '<%% %s %%>', { 'prefix' : '1%>', 'suffix' : '<%#' }),
        (1, 1, '<%%! %s %%>', { 'prefix' : '1%>', 'suffix' : '<%#' }),
        (1, 1, '<%% %s=1 %%>', { 'prefix' : '1%>', 'suffix' : '<%#' }),
        (1, 1, '<%% a=%s %%>', { 'prefix' : '1%>', 'suffix' : '<%#' }),
        (1, 1, '<%% a=\'%s\' %%>', { 'prefix' : '1\'%>', 'suffix' : '<%#' }),
        (1, 1, '<%% a="%s" %%>', { 'prefix' : '1"%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a="""%s""" %%>', { 'prefix' : '1"""%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=range(%s) %%>', { 'prefix' : '1)%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=\'\'.join(\'%s\') %%>', { 'prefix' : '1\')%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=\'\'.join("%s") %%>', { 'prefix' : '1\")%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=\'\'.join("""%s""") %%>', { 'prefix' : '1""")%>', 'suffix' : '<%#' }),


        (1, 3, '<%% a=[%s] %%>', { 'prefix' : '1]%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=[\'%s\'] %%>', { 'prefix' : '1\']%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=["%s"] %%>', { 'prefix' : '1"]%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a=["""%s"""] %%>', { 'prefix' : '1"""]%>', 'suffix' : '<%#' }),
        (1, 5, '<%% a=set([%s]) %%>', { 'prefix' : '1])%>', 'suffix' : '<%#' }),
        (1, 5, '<%% a=set([\'%s\']) %%>', { 'prefix' : '1\'])%>', 'suffix' : '<%#' }),
        (1, 5, '<%% a=set(["%s"]) %%>', { 'prefix' : '1"])%>', 'suffix' : '<%#' }),
        (1, 5, '<%% a=set(["""%s"""]) %%>', { 'prefix' : '1"""])%>', 'suffix' : '<%#' }),

        (1, 3, '<%% a={%s} %%>', { 'prefix' : '1}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={1:%s} %%>', { 'prefix' : '1}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={1:\'%s\'} %%>', { 'prefix' : '1\'}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={1:"%s"} %%>', { 'prefix' : '1"}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={1:"""%s"""} %%>', { 'prefix' : '1"""}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={3:2, %s:1} %%>', { 'prefix' : '1:1}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={\'%s\':1}] %%>', { 'prefix' : '1\'}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={"%s":1}] %%>', { 'prefix' : '1"}%>', 'suffix' : '<%#' }),
        (1, 3, '<%% a={"""%s""":1} %%>', { 'prefix' : '1"""}%>', 'suffix' : '<%#' }),

        # if and for blocks context
        (5, 5, '%% if %s:\n%% endif', { 'prefix' : '1:#\n', 'suffix' : '\n' }),
        (5, 5, '%% for a in %s:\n%% endfor', { 'prefix' : '"1":#\n', 'suffix' : '\n' }),
        (5, 5, '%% if %s==1:\n%% endif', { 'prefix' : '1:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if \'%s\'==1:\n%% endif', { 'prefix' : '1\':#\n', 'suffix' : '\n' }),
        (5, 5, '%% if "%s"==1:\n%% endif', { 'prefix' : '1":#\n', 'suffix' : '\n' }),
        (5, 5, '%% if """%s"""==1:\n%% endif', { 'prefix' : '1""":#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, %s)==1:\n%% endif', { 'prefix' : '1):#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, \'%s\')==1:\n%% endif', { 'prefix' : '1\'):#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, "%s")==1:\n%% endif', { 'prefix' : '1"):#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, """%s""")==1:\n%% endif', { 'prefix' : '1"""):#\n', 'suffix' : '\n' }),

        (5, 5, '%% if [%s]==1:\n%% endif', { 'prefix' : '1]:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if [\'%s\']==1:\n%% endif', { 'prefix' : '1\']:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if ["%s"]==1:\n%% endif', { 'prefix' : '1"]:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if ["""%s"""]==1:\n%% endif', { 'prefix' : '1"""]:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, [%s])==1:\n%% endif', { 'prefix' : '1]):#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, [\'%s\'])==1:\n%% endif', { 'prefix' : '1\']):#\n', 'suffix' : '\n' }),
        (5, 5, '%% if (1, ["%s"])==1:\n%% endif', { 'prefix' : '1"]):#\n', 'suffix' : '\n' }),

        (5, 5, '%% if (1, ["""%s"""])==1:\n%% endif', { 'prefix' : '1"""]):#\n', 'suffix' : '\n' }),

        (5, 5, '%% for a in {%s}:\n%% endfor', { 'prefix' : '1}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {%s:1}==1:\n%% endif', { 'prefix' : '1}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {\'%s\':1}==1:\n%% endif', { 'prefix' : '1\'}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {"%s":1}==1:\n%% endif', { 'prefix' : '1"}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {"""%s""":1}==1:\n%% endif', { 'prefix' : '1"""}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {1:%s}==1:\n%% endif', { 'prefix' : '1}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {1:\'%s\'}==1:\n%% endif', { 'prefix' : '1\'}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {1:"%s"}==1:\n%% endif', { 'prefix' : '1"}:#\n', 'suffix' : '\n' }),
        (5, 5, '%% if {1:"""%s"""}==1:\n%% endif', { 'prefix' : '1"""}:#\n', 'suffix' : '\n' }),

        # Mako blocks. Skip <%block> which doesn't seem affecting the standard inj
        # Inejcting includes e.g. '<%%include file="%s"/>' generates a missing file exception
        (5, 1, '<%%doc> %s </%%doc>', { 'prefix' : '</%doc>', 'suffix' : '<%doc>' }),
        #(5, 1, '<%%def name="a(x)"> %s </%%def>', { 'prefix' : '</%def>', 'suffix' : '<%def name="t(x)">' }),
        (5, 1, '<%%text> %s </%%text>', { 'prefix' : '</%text>', 'suffix' : '<%text>' }),

    ]

    def test_reflection_limit(self):
        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/limit/mako?tpl=%s&inj=*&limit=20' % template,
            'injection_tag': '*',
            'technique': 'R'
        })

        Mako(channel).detect()

        expected_data = { 'unreliable_render' : self.expected_data['render'], 'unreliable' : 'Mako' }

        self.assertEqual(channel.data, expected_data)
