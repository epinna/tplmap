from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from plugins.engines.smarty import Smarty
from core.http import Channel
from utils.loggers import log

def checkTemplateInjection(args):
    
    channel = Channel(url = args["url"][0])
    mako = Mako(channel)
    jinja2 = Jinja2(channel)
    smarty = Smarty(channel)