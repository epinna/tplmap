import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.ejs import Ejs
from basetest import BaseTest


class EjsTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'ejs',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': """%(code)s""",
        'header': """<%%- '%(header)s'+""",
        'trailer': """+'%(trailer)s' %%>""",
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'ejs',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'javascript',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/ejs?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/ejs?inj=*&tpl=%s'
    plugin = Ejs


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (1, 0, "<% %s %>", { 'prefix': '1%>', 'suffix' : '<%#' }),
        (1, 1, "<% '%s' %>", { 'prefix': "1'%>", 'suffix' : '<%#' }),
        (1, 1, '<% "%s" %>', { 'prefix': '1"%>', 'suffix' : '<%#' }),
        (1, 0, '<%= %s %>', { 'prefix': '1%>', 'suffix' : '<%#' }),
        (1, 0, '<%- %s %>', { 'prefix': '1%>', 'suffix' : '<%#' }),
        (1, 0, '<%# %s %>', { 'prefix': '1%>', 'suffix' : '<%#' }),
        (1, 0, '<%_ %s %>', { 'prefix': '1%>', 'suffix' : '<%#' }),
        (1, 0, '<% %s -%>', { 'prefix': '1%>', 'suffix' : '<%#' }),
        (1, 0, '<% %s _%>', { 'prefix': '1%>', 'suffix' : '<%#' }),
        (2, 1, "<%- include('/etc/resolv.conf%s') %>", { 'prefix': "')%>", 'suffix' : '<%#' }),
        (2, 2, '<%- include("/etc/resolv.conf%s") %>', { 'prefix': '")%>', 'suffix' : '<%#' }),
        (3, 0, "<% 456/* AAA %s */-123 %>", { 'prefix': '*/%>', 'suffix': '<%#' }),
    ]
