from utils import rand
from utils.loggers import log
import re
import itertools

class Plugin:

    def __init__(self, channel):

        # HTTP channel
        self.channel = channel

        # Plugin name
        self.plugin = self.__class__.__name__

    def detect(self):

        context_num = len([c for c in self.contexts if (c.get('level') <= self.channel.args.get('level'))])

        # Print what it's going to be tested
        log.info('Testing reflection on text context on %s with tag %s' % (
                self.plugin,
                repr(self.render_tag % ({'payload' : '*' })).strip("'"),
            )
        )

        # If tags found previously are the same as current plugin, skip context detection
        if not (
                self.get('render_tag') == self.render_tag and
                self.get('header_tag') == self.header_tag and
                self.get('trailer_tag') == self.trailer_tag
            ):
            self._detect_context()

        # If no weak reflection has been detected so far
        elif not self.get('render_tag'):

            # Start detection
            self._detect_context()

            # Print message if header or trailer are still unset
            if self.get('header_tag') == None or self.get('trailer_tag') == None:
                if self.get('render_tag'):
                    log.info('Detected unreliable reflection with tag %s, continuing' % (repr(self.get('render_tag') % ({'payload' : '*' })).strip("'")))

        # Exit if header or trailer are still different
        if not (
                self.get('render_tag') == self.render_tag and
                self.get('header_tag') == self.header_tag and
                self.get('trailer_tag') == self.trailer_tag
            ):
            return

        prefix = self.get('prefix', '')
        render_tag = self.get('render_tag') % ({'payload' : '*' })
        suffix = self.get('suffix', '')
        log.info('Confirmed reflection with tag \'%s%s%s\' by %s plugin' % (
            repr(prefix).strip("'"),
            repr(render_tag).strip("'"),
            repr(suffix).strip("'"),
            self.plugin)
        )

        self.detect_engine()

        # Return if engine is still unset
        if not self.get('engine'):
            return

        self.detect_eval()
        self.detect_exec()
        self.detect_write()
        self.detect_read()


    """
    First detection of the injection and the context.
    """
    def _detect_context(self):

        # Prepare base operation to be evalued server-side
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)
        expected = str(randA*randB)

        # Prepare first detection payload and header
        payload = self.render_tag % ({ 'payload': '%s*%s' % (randA, randB) })
        header_rand = rand.randint_n(10)
        header = self.header_tag % ({ 'header' : header_rand })
        trailer_rand = rand.randint_n(10)
        trailer = self.trailer_tag % ({ 'trailer' : trailer_rand })

        log.debug('%s: Trying to inject in text context' % self.plugin)

        # First probe with payload wrapped by header and trailer, no suffex or prefix
        if expected == self.inject(
                payload = payload,
                header = header,
                trailer = trailer,
                header_rand = header_rand,
                trailer_rand = trailer_rand,
                prefix = '',
                suffix = ''
            ):
            self.set('render_tag', self.render_tag)
            self.set('header_tag', self.header_tag)
            self.set('trailer_tag', self.trailer_tag)
            return

        log.debug('%s: Injection in text context failed, trying to inject in code context' % self.plugin)


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

            closures = self._generate_closures(ctx)

            prefix = ctx.get('prefix', '%(closure)s') % ( { 'closure' : '' } )
            log.info('Testing code context escape %s*%s with %i closures%s' % (
                            repr(prefix).strip("'"),
                            repr(suffix).strip("'"),
                            len(closures),
                            ' (level %i)' % (ctx.get('level', 1))
                    )
            )

            for closure in closures:

                # Format the prefix with closure
                prefix = ctx.get('prefix', '%(closure)s') % ( { 'closure' : closure } )
                if expected == self.inject(
                        payload = payload,
                        header = header,
                        trailer = trailer,
                        header_rand = header_rand,
                        trailer_rand = trailer_rand,
                        prefix = prefix,
                        suffix = suffix
                    ):
                    self.set('render_tag', self.render_tag)
                    self.set('header_tag', self.header_tag)
                    self.set('trailer_tag', self.trailer_tag)
                    self.set('prefix', prefix)
                    self.set('suffix', suffix)

                    return

        log.debug('%s: Injection in code context failed, trying to inject only payload with no header' % self.plugin)

        # As last resort, just inject without header and trailer and
        # see if expected is contained in the response page
        if expected in self.inject(
                payload = payload,
                header = '',
                trailer = '',
                header_rand = 0,
                trailer_rand = 0,
                prefix = '',
                suffix = ''
            ):
            self.set('render_tag', self.render_tag)
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
    Detect file write capability
    """
    def detect_write(self):
        pass

    """
    Detect file read capability
    """
    def detect_read(self):
        pass

    """
    Inject shell commands
    """
    def execute(self, code):
        pass

    """
    Inject code
    """
    def evaluate(self, command):
        pass

    """
    Download file
    """
    def read(self, remote_path):
        pass

    """
    Upload file
    """
    def write(self, data, remote_path):
        pass

    """
    Inject the payload.

    All the passed parameter must be already rendered. The parameters which are not passed, will be
    picked from self.channel.data dictionary and rendered at the moment.
    """
    def inject(self, payload, header = None, header_rand = None, trailer = None, trailer_rand = None, prefix = None, suffix = None):

        header_rand = rand.randint_n(10) if header_rand == None else header_rand
        header = self.get('header_tag', '%(header)s') % ({ 'header' : header_rand }) if header == None else header

        trailer_rand = rand.randint_n(10) if trailer_rand == None else trailer_rand
        trailer = self.get('trailer_tag', '%(trailer)s') % ({ 'trailer' : trailer_rand }) if trailer == None else trailer

        prefix = self.get('prefix', '') if prefix == None else prefix
        suffix = self.get('suffix', '') if suffix == None else suffix

        injection = prefix + header + payload + trailer + suffix
        log.debug('[request %s] %s' % (self.plugin, repr(self.channel.url)))

        result_raw = self.channel.req(injection)
        result = ''

        # Cut the result using the header and trailer if specified
        if header:
            before,_,result_after = result_raw.partition(str(header_rand))
        if trailer and result_after:
            result,_,after = result_after.partition(str(trailer_rand))
            
        return result.strip()

    def set(self, key, value):
        self.channel.data[key] = value

    def get(self, key, default = None):
        return self.channel.data.get(key, default)

    def _generate_closures(self, ctx):

        ctx_closures_names_dict_of_lists = ctx.get('closures', {})

        closures = []

        # Loop all the closure names
        for ctx_closure_level, ctx_closure_lists_of_lists_of_names in ctx_closures_names_dict_of_lists.items():

            # If --force-level skip any other level
            force_level = self.channel.args.get('force_level')
            if force_level and force_level[1] and ctx_closure_level != int(force_level[1]):
                continue

            # Skip any closure list which is above the required level
            if not force_level and ctx_closure_level > self.channel.args.get('level'):
                continue

            closure_matrix = []
            # Expand the names
            for ctx_closure_lists_of_names in ctx_closure_lists_of_lists_of_names:

                # This will be merged in a single list
                closure_matrix.append(list(itertools.chain(*[ self.language_closures[n] for n in ctx_closure_lists_of_names])))

            closures += [ ''.join(x) for x in itertools.product(*closure_matrix) ]

        closures = sorted(set(closures), key=len)

        # Return it
        return closures
