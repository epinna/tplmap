from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from plugins.engines.twig import Twig
from plugins.engines.freemarker import Freemarker
from plugins.engines.velocity import Velocity
from plugins.engines.jade import Jade
from core.channel import Channel
from utils.loggers import log

plugins = [
    Mako,
    Jinja2,
    Twig,
    Freemarker,
    Velocity,
    Jade
]

def checkTemplateInjection(args):

    channel = Channel(args)
    current_plugin = None

    # Iterate all the available plugins until
    # the first template engine is detected.
    for plugin in plugins:
        current_plugin = plugin(channel)
        current_plugin.detect()

        if channel.data.get('engine'):
            break

    # Kill execution if no engine have been found
    if not channel.data.get('engine'):
        log.fatal("""Tested parameters appear to be not injectable. Try to increase '--level' value to perform more tests.""")
        return

    # If there are no operating system actions, exit
    if not any(f for f,v in args.items() if f in ('os_cmd', 'os_shell') and v ):
        log.warn("""Tested parameters have been found injectable.""")
        if channel.data.get('exec'):
            log.warn("""Try options '--os-cmd' or '--os-shell' to access the underlying operating system.""")

    # Execute operating system commands
    if channel.data.get('exec'):

        if args.get('os_cmd'):
            print current_plugin.execute(args.get('os_cmd'))
        elif args.get('os_shell'):

            while True:
                command = raw_input('$ ')
                print current_plugin.execute(command.strip())

    # Execute operating system commands
    if channel.data.get('engine'):

        if args.get('tpl_code'):
            print current_plugin.inject(args.get('os_cmd'))
        elif args.get('tpl_shell'):
            log.warn('Inject multi-line code on the template engine. Double-return to send the code.')

            lines = []
            while True:
                command = raw_input('%s %i> ' % (channel.data.get('engine'), len(lines)))
                lines.append(command.strip())

                # Send in case of double-return
                if command.strip() == '' and lines[-1] == '':
                    print current_plugin.inject('\n'.join(lines[:-1]))
                    lines = []
