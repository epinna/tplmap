from core.plugin import Plugin
from utils import rand
from utils.loggers import log
import re


class Check(Plugin):

    def __init__(self, channel):

        # HTTP channel
        self.channel = channel

    def detect(self):

        # Skip detection if render, header and trailer tags article
        # same as this module
        if not (
                self.get('render_tag') == self.render_tag and
                self.get('header_tag') == self.header_tag and
                self.get('trailer_tag') == self.trailer_tag
            ):
            self._detect_context()

        # Return if header or trailer are still unset
        if self.get('header_tag') == None or self.get('trailer_tag') == None:

            if self.get('render_tag'):
                log.warn('Weak Reflection detected with tag \'%s\', continuing' % (self.get('render_tag')))

            return

        log.warn('Reflection detected with tag \'%s%s%s\'' % (self.get('prefix', ''), self.get('render_tag'), self.get('suffix', '')))

        self.detect_engine()

        # Return if engine is still unset
        if not self.get('engine'):
            return

        log.warn('Template engine \'%s\' detected' % self.get('engine'))

        self.detect_eval()

        # Return if eval is unset
        if not self.get('eval'):
            return

        log.warn('Code evaluation in \'%s\' detected' % self.get('eval'))

        self.detect_exec()

        # Return if eval is unset
        if not self.get('exec'):
            return
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.get('os', 'undetected')
            )
        )

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
        header_rand = rand.randint_n(3)
        header = self.header_tag % ({ 'header' : header_rand })
        trailer_rand = rand.randint_n(3)
        trailer = self.trailer_tag % ({ 'trailer' : trailer_rand })

        log.debug('Trying to inject in text context')

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

        log.debug('Injection in text context failed, trying to inject in code context')

        # If not found, try to inject all the prefix and suffix pairs falling below the level
        for ctx in self.contexts:
            if self.channel.args.get('level') > ctx.get('level', 1):
                break
            if expected == self.inject(
                    payload = payload,
                    header = header,
                    trailer = trailer,
                    header_rand = header_rand,
                    trailer_rand = trailer_rand,
                    prefix = ctx.get('prefix', ''),
                    suffix = ctx.get('suffix', '')
                ):
                self.set('render_tag', self.render_tag)
                self.set('header_tag', self.header_tag)
                self.set('trailer_tag', self.trailer_tag)
                self.set('prefix', ctx.get('prefix', ''))
                self.set('suffix', ctx.get('suffix', ''))

                return

        log.debug('Injection in code context failed, trying to inject only payload with no header')

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
    Detect shell command execution:
    """
    def detect_exec(self):
        pass

    """
    Inject the payload.

    All the passed parameter must be already rendered. The parameters which are not passed, will be
    picked from self.channel.data dictionary and rendered at the moment.
    """
    def inject(self, payload, header = None, header_rand = None, trailer = None, trailer_rand = None, prefix = None, suffix = None):

        header_rand = rand.randint_n(3) if header_rand == None else header_rand
        header = self.get('header_tag', '%(header)s') % ({ 'header' : header_rand }) if header == None else header

        trailer_rand = rand.randint_n(3) if trailer_rand == None else trailer_rand
        trailer = self.get('trailer_tag', '%(trailer)s') % ({ 'trailer' : trailer_rand }) if trailer == None else trailer

        prefix = self.get('prefix', '') if prefix == None else prefix
        suffix = self.get('suffix', '') if suffix == None else suffix

        injection = prefix + header + payload + trailer + suffix
        result = self.channel.req(injection)
        log.debug('[request]\n  > %s\n  < %s' % (injection.replace('\n', '\n  > '), result.replace('\n', '  \n  < ')) )

        # Cut the result using the header and trailer if specified
        if header:
            before,_,result = result.partition(str(header_rand))
        if trailer:
            result,_,after = result.partition(str(trailer_rand))

        return result.strip()

    def set(self, key, value):
        self.channel.data[key] = value

    def get(self, key, default = None):
        return self.channel.data.get(key, default)
