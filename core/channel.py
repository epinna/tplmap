import requests
from utils.loggers import log
import urlparse

class Channel:
    
    def __init__(self, url):
        
        self.url = url
        self.data = {}
        
        self.get_params = {}
        self.get_placeholders = []
        
        if '*' not in self.url:
            log.warn("no GET or parameter(s) found for testing ")

        self._parse_get()

    def _parse_get(self):
        
        params_dict_list = urlparse.parse_qs(urlparse.urlsplit(self.url).query)
        
        for param, value_list in params_dict_list.items():
            self.get_params[param] = value_list
            
            if any(x for x in value_list if '*' in x):
                self.get_placeholders.append(param)
                log.warn('Found placeholder in parameter \'%s\'' % param)
                
            
    def req(self, injection):
        
        # Get base URL
        url_string = self.url.split("?")[0]
        get_placeholder = self.get_placeholders[0]
            
        get_params = self.get_params.copy()
        get_params[get_placeholder] = injection
        return requests.get(url_string, params = get_params).text
        