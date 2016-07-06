import requests
from utils.loggers import log
import urlparse

class Channel:
    
    def __init__(self, args):
        
        self.args = args
        
        self.url = self.args.get('url')
        self.base_url = self.url.split("?")[0] if '?' in self.url else self.url
        
        self.data = {}
        
        self.get_params = {}
        self.get_placeholders = []

        self.post_params = {}
        self.post_placeholders = []

        self.header_params = {}
        self.header_placeholders = []
        
        self._parse_get()
        self._parse_post()
        self._parse_header()
        self._parse_method()
                
        if len(self.post_placeholders + self.get_placeholders) > 1:
            log.warn('Error, multiple placeholder in parameters')
    
    def _parse_method(self):
        
        if self.args.get('method'):
            self.http_method = self.args.get('method')
        elif self.post_params:
            self.http_method = 'POST'
        else:
            self.http_method = 'GET'    
    
    def _parse_header(self):
        for param_value in self.args.get('headers', '[]'):
            
            if ':' not in param_value:
                continue
            
            param, value = param_value.split(':')
            param = param.strip()
            value = value.strip()
            
            self.header_params[param] = value
            
            if '*' in value:
                self.header_placeholders.append(param)
                log.warn('Found placeholder in Header \'%s\'' % param)
        
    def _parse_post(self):
        
        for param_value in self.args.get('post_data', '[]'):
            
            if '=' not in param_value:
                continue
            
            param, value = param_value.split('=')
            
            self.post_params[param] = value
            
            if '*' in value:
                self.post_placeholders.append(param)
                log.warn('Found placeholder in POST parameter \'%s\'' % param)

    def _parse_get(self):
        
        params_dict_list = urlparse.parse_qs(urlparse.urlsplit(self.url).query)
        
        for param, value_list in params_dict_list.items():
            self.get_params[param] = value_list
            
            if any(x for x in value_list if '*' in x):
                self.get_placeholders.append(param)
                log.warn('Found placeholder in GET parameter \'%s\'' % param)
                
            
    def req(self, injection):
        
        # Inject 
        get_params = {}
        if self.get_placeholders:
            get_placeholder = self.get_placeholders[0]    
            get_params = self.get_params.copy()
            get_params[get_placeholder] = injection
        
        post_params = {}
        if self.post_placeholders:
            post_placeholder = self.post_placeholders[0]    
            post_params = self.post_params.copy()
            post_params[post_placeholder] = injection
            
        header_params = {}
        if self.header_placeholders:
            
            if '\n' in injection:
                log.debug('Skip payload with not compatible character for headers')
            else:
                header_placeholder = self.header_placeholders[0]    
                header_params = self.header_params.copy()
                header_params[header_placeholder] = injection
                
        return requests.request(
            method = self.http_method, 
            url = self.base_url, 
            params = get_params,
            data = post_params,
            headers = header_params
            ).text
    