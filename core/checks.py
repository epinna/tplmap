from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from plugins.engines.twig import Twig
from plugins.engines.freemarker import Freemarker
from core.channel import Channel
from utils.loggers import log

def checkTemplateInjection(args):
    
    channel = Channel(url = args["url"][0])
        
    # Check Smarty 
    Smarty(channel)
    if channel.data.get('engine'):
        return
        
    # Probe if Mako
    Mako(channel)
    if channel.data.get('engine'):
        return
            
    # Probe if Ninja2
    Jinja2(channel)
    if channel.data.get('engine'):
        return
            
    # Probe Twig
    Twig(channel)
    if channel.data.get('engine'):
        return
    
    # Probe Freemarker
    Freemarker(channel)
    if channel.data.get('engine'):
        return