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

    # Iterate all the available plugins until
    # the first template engine is detected. 
    for plugin in plugins:
        plugin(channel).detect()
        
        if channel.data.get('engine'):
            break
