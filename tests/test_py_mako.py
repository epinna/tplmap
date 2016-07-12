import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel
from utils import rand
from utils import strings
from basetest import BaseTest

class MakoTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'eval' : 'python' ,
        'exec' : True,
        'read': True,
        'write': True,
        'trailer_tag': '${%(trailer)s}',
        'header_tag': '${%(header)s}',
        'render_tag': '${%(payload)s}',
    }

    url = 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*'
    plugin = Mako

    reflection_tests = [
        # Text context
        (1, '%s', {}),
        (1, 'AAA%sAAA', {}),

        # Reflecting tag ${} context
        (1, '${%s}', { 'prefix': '1}', 'suffix' : '' }),
        (2, '${ \'%s\' }', { 'prefix': '1\'}', 'suffix' : '' }),
        (2, '${ "%s" }', { 'prefix': '1"}', 'suffix' : '' }),
        (2, '${ """%s""" }', { 'prefix': '1"""}', 'suffix' : '' }),
        (3, '${ range(%s) }', { 'prefix': '1)}', 'suffix' : '' }),
        (3, '${ set(\'%s\') }', { 'prefix': '1\')}', 'suffix' : '' }),
        (3, '${ set("%s") }', { 'prefix': '1")}', 'suffix' : '' }),
        (3, '${ set("""%s""") }', { 'prefix': '1""")}', 'suffix' : '' }),

        (4, '${[%s]}', { 'prefix': '1]}', 'suffix' : '' }),
        (4, '${ [\'%s\'] }', { 'prefix': '1\']}', 'suffix' : '' }),
        (4, '${ ["%s"] }', { 'prefix': '1"]}', 'suffix' : '' }),
        (4, '${ ["""%s"""] }', { 'prefix': '1"""]}', 'suffix' : '' }),
        (4, '${ set([%s]) }', { 'prefix': '1])}', 'suffix' : '' }),
        (4, '${ set([\'%s\']) }', { 'prefix': '1\'])}', 'suffix' : '' }),
        (4, '${ set(["%s"]) }', { 'prefix': '1"])}', 'suffix' : '' }),
        (4, '${ set(["""%s"""]) }', { 'prefix': '1"""])}', 'suffix' : '' }),

        (5, '${{%s}}', { 'prefix': '1:1}}', 'suffix' : '' }),
        (5, '${{1:%s}}', { 'prefix': '1}}', 'suffix' : '' }),
        (5, '${ {1:\'%s\'} }', { 'prefix': '1\'}}', 'suffix' : '' }),
        (5, '${ {1:"%s"} }', { 'prefix': '1"}}', 'suffix' : '' }),
        (5, '${ {1:"""%s"""} }', { 'prefix': '1"""}}', 'suffix' : '' }),
        (5, '${{%s:1}}', { 'prefix': '1:1}}', 'suffix' : '' }),
        (5, '${ {\'%s\':1} }', { 'prefix': '1\':1}}', 'suffix' : '' }),
        (5, '${ {"%s":1} }', { 'prefix': '1":1}}', 'suffix' : '' }),
        (5, '${ {"""%s""":1} }', { 'prefix': '1""":1}}', 'suffix' : '' }),

        # Code blocks context
        (1, '<%% %s %%>', { 'prefix' : '%>', 'suffix' : '<%#' }),
        (1, '<%%! %s %%>', { 'prefix' : '%>', 'suffix' : '<%#' }),
        (1, '<%% %s=1 %%>', { 'prefix' : '%>', 'suffix' : '<%#' }),
        (2, '<%% a=%s %%>', { 'prefix' : '1%>', 'suffix' : '<%#' }),
        (2, '<%% a=\'%s\' %%>', { 'prefix' : '1\'%>', 'suffix' : '<%#' }),
        (2, '<%% a="%s" %%>', { 'prefix' : '1"%>', 'suffix' : '<%#' }),
        (2, '<%% a="""%s""" %%>', { 'prefix' : '1"""%>', 'suffix' : '<%#' }),
        (3, '<%% a=range(%s) %%>', { 'prefix' : '1)%>', 'suffix' : '<%#' }),
        (3, '<%% a=\'\'.join(\'%s\') %%>', { 'prefix' : '1\')%>', 'suffix' : '<%#' }),
        (3, '<%% a=\'\'.join("%s") %%>', { 'prefix' : '1\")%>', 'suffix' : '<%#' }),
        (3, '<%% a=\'\'.join("""%s""") %%>', { 'prefix' : '1""")%>', 'suffix' : '<%#' }),

        (4, '<%% a=[%s] %%>', { 'prefix' : '1]%>', 'suffix' : '<%#' }),
        (4, '<%% a=[\'%s\'] %%>', { 'prefix' : '1\']%>', 'suffix' : '<%#' }),
        (4, '<%% a=["%s"] %%>', { 'prefix' : '1"]%>', 'suffix' : '<%#' }),
        (4, '<%% a=["""%s"""] %%>', { 'prefix' : '1"""]%>', 'suffix' : '<%#' }),
        (4, '<%% a=set([%s]) %%>', { 'prefix' : '1])%>', 'suffix' : '<%#' }),
        (4, '<%% a=set([\'%s\']) %%>', { 'prefix' : '1\'])%>', 'suffix' : '<%#' }),
        (4, '<%% a=set(["%s"]) %%>', { 'prefix' : '1"])%>', 'suffix' : '<%#' }),
        (4, '<%% a=set(["""%s"""]) %%>', { 'prefix' : '1"""])%>', 'suffix' : '<%#' }),

        (5, '<%% a={%s} %%>', { 'prefix' : '1:1}%>', 'suffix' : '<%#' }),
        (5, '<%% a={1:%s} %%>', { 'prefix' : '1}%>', 'suffix' : '<%#' }),
        (5, '<%% a={1:\'%s\'} %%>', { 'prefix' : '1\'}%>', 'suffix' : '<%#' }),
        (5, '<%% a={1:"%s"} %%>', { 'prefix' : '1"}%>', 'suffix' : '<%#' }),
        (5, '<%% a={1:"""%s"""} %%>', { 'prefix' : '1"""}%>', 'suffix' : '<%#' }),
        (5, '<%% a={%s:1} %%>', { 'prefix' : '1:1}%>', 'suffix' : '<%#' }),
        (5, '<%% a={\'%s\':1}] %%>', { 'prefix' : '1\':1}%>', 'suffix' : '<%#' }),
        (5, '<%% a={"%s":1}] %%>', { 'prefix' : '1":1}%>', 'suffix' : '<%#' }),
        (5, '<%% a={"""%s""":1} %%>', { 'prefix' : '1""":1}%>', 'suffix' : '<%#' }),



        # if and for blocks context
        (2, '%% if %s:\n%% endif', { 'prefix' : '\'a\':#\n', 'suffix' : '\n' }),
        (2, '%% for a in %s:\n%% endfor', { 'prefix' : '\'a\':#\n', 'suffix' : '\n' }),
        (2, '%% if %s==1:\n%% endif', { 'prefix' : '\'a\':#\n', 'suffix' : '\n' }),
        (2, '%% if \'%s\'==1:\n%% endif', { 'prefix' : 'a\':#\n', 'suffix' : '\n' }),
        (2, '%% if "%s"==1:\n%% endif', { 'prefix' : 'a":#\n', 'suffix' : '\n' }),
        (2, '%% if """%s"""==1:\n%% endif', { 'prefix' : 'a""":#\n', 'suffix' : '\n' }),
        (3, '%% if (%s)==1:\n%% endif', { 'prefix' : '\'a\'):#\n', 'suffix' : '\n' }),
        (3, '%% if (\'%s\')==1:\n%% endif', { 'prefix' : 'a\'):#\n', 'suffix' : '\n' }),
        (3, '%% if ("%s")==1:\n%% endif', { 'prefix' : 'a"):#\n', 'suffix' : '\n' }),
        (3, '%% if ("""%s""")==1:\n%% endif', { 'prefix' : 'a"""):#\n', 'suffix' : '\n' }),

        (4, '%% if [%s]==1:\n%% endif', { 'prefix' : '\'a\']:#\n', 'suffix' : '\n' }),
        (4, '%% if [\'%s\']==1:\n%% endif', { 'prefix' : 'a\']:#\n', 'suffix' : '\n' }),
        (4, '%% if ["%s"]==1:\n%% endif', { 'prefix' : 'a"]:#\n', 'suffix' : '\n' }),
        (4, '%% if ["""%s"""]==1:\n%% endif', { 'prefix' : 'a"""]:#\n', 'suffix' : '\n' }),
        (4, '%% if ([%s])==1:\n%% endif', { 'prefix' : '\'a\']):#\n', 'suffix' : '\n' }),
        (4, '%% if ([\'%s\'])==1:\n%% endif', { 'prefix' : 'a\']):#\n', 'suffix' : '\n' }),
        (4, '%% if (["%s"])==1:\n%% endif', { 'prefix' : 'a"]):#\n', 'suffix' : '\n' }),
        (4, '%% if (["""%s"""])==1:\n%% endif', { 'prefix' : 'a"""]):#\n', 'suffix' : '\n' }),


        (5, '%% for a in {%s}:\n%% endfor', { 'prefix' : '1:1}:#\n', 'suffix' : '\n' }),
        (5, '%% if {%s:1}==1:\n%% endif', { 'prefix' : '1:1}:#\n', 'suffix' : '\n' }),
        (5, '%% if {\'%s\':1}==1:\n%% endif', { 'prefix' : 'a\':1}:#\n', 'suffix' : '\n' }),
        (5, '%% if {"%s":1}==1:\n%% endif', { 'prefix' : 'a":1}:#\n', 'suffix' : '\n' }),
        (5, '%% if {"""%s""":1}==1:\n%% endif', { 'prefix' : 'a""":1}:#\n', 'suffix' : '\n' }),
        (5, '%% if {1:%s}==1:\n%% endif', { 'prefix' : '1}:#\n', 'suffix' : '\n' }),
        (5, '%% if {1:\'%s\'}==1:\n%% endif', { 'prefix' : 'a\'}:#\n', 'suffix' : '\n' }),
        (5, '%% if {1:"%s"}==1:\n%% endif', { 'prefix' : 'a"}:#\n', 'suffix' : '\n' }),
        (5, '%% if {1:"""%s"""}==1:\n%% endif', { 'prefix' : 'a"""}:#\n', 'suffix' : '\n' }),


        # Mako blocks. Skip <%block> which doesn't seem affecting the standard inj
        # Inejcting includes e.g. '<%%include file="%s"/>' generates a missing file exception
        (5, '<%%doc> %s </%%doc>', { 'prefix' : '</%doc>', 'suffix' : '<%doc>' }),
        #(5, '<%%def name="a(x)"> %s </%%def>', { 'prefix' : '</%def>', 'suffix' : '<%def name="t(x)">' }),
        (5, '<%%text> %s </%%text>', { 'prefix' : '</%text>', 'suffix' : '<%text>' }),

    ]

    def test_reflection_limit(self):
        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/limit/mako?tpl=%s&inj=*&limit=6' % template
        })

        Mako(channel).detect()

        expected_data = { 'render_tag' : self.expected_data['render_tag'] }

        self.assertEqual(channel.data, expected_data)
