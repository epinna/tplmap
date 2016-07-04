from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from plugins.engines.twig import Twig
from plugins.engines.freemarker import Freemarker
from plugins.engines.velocity import Velocity
from plugins.engines.jade import Jade
from core.channel import Channel
from utils.loggers import log

def checkTemplateInjection(args):
    
    channel = Channel(args)

    # Probe Jade
    Jade(channel).detect()
    if channel.data.get('engine'):
        return
        
    # Check Smarty 
    Smarty(channel).detect()
    if channel.data.get('engine'):
        return
        
    # Probe if Mako
    Mako(channel).detect()
    if channel.data.get('engine'):
        return
            
    # Probe if Ninja2
    Jinja2(channel).detect()
    if channel.data.get('engine'):
        return
            
    # Probe Twig
    Twig(channel).detect()
    if channel.data.get('engine'):
        return
    
    # Probe Freemarker
    Freemarker(channel).detect()
    if channel.data.get('engine'):
        return
        
    # Probe Velocity
    Velocity(channel).detect()
    if channel.data.get('engine'):
        return