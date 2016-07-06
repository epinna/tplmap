from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
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
