from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from plugins.engines.twig import Twig
from core.channel import Channel
from utils.loggers import log

def checkTemplateInjection(args):
    
    channel = Channel(url = args["url"][0])
    
    # Probe if Mako
    mako = Mako(channel)
    
    # Probe if ninja
    jinja2 = Jinja2(channel)
    
    # Check Smarty and Jinja2 
    smarty = Smarty(channel)
    twig = Twig(channel)