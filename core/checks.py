from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from plugins.engines.twig import Twig
from core.channel import Channel
from utils.loggers import log

def checkTemplateInjection(args):

    channel = Channel(args)

    # Probe if Mako
    Mako(channel).detect()
    if channel.data.get('engine'):
        return

    # Probe if Jinja2
    Jinja2(channel).detect()
    if channel.data.get('engine'):
        return

    # Probe if Smarty
    Smarty(channel).detect()
    if channel.data.get('engine'):
        return

    # Probe if Twig
    Twig(channel).detect()
    if channel.data.get('engine'):
        return
