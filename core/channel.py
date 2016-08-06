import requests
from utils.loggers import log
import urlparse

class Channel:

    def __init__(self, args):

        self.args = args

        # Consider # as part of the query string, end encode \n
        self.url = self.args.get('url').replace('#', '%23').replace('\\n', '%0A')

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

        if self.args.get('request'):
            self.http_method = self.args.get('request')
        elif self.post_params:
            self.http_method = 'POST'
        else:
            self.http_method = 'GET'

    def _parse_header(self):
        
        for param_value in self.args.get('headers').split('\\r\\n'):

            if ':' not in param_value:
                continue

            param, value = param_value.split(':')
            param = param.strip()
            value = value.strip()

            self.header_params[param] = value

            if '*' in value:
                self.header_placeholders.append(param)
                log.warn('Found placeholder in Header \'%s\'' % param)
                
        # Set user agent if not set already
        user_agent = self.args.get('user_agent')
        if not user_agent:
            user_agent = 'tplmap/%s' % self.args.get('version')
            
        if not 'User-Agent' in self.header_params:
            self.header_params['User-Agent'] = user_agent

    def _parse_post(self):

        if self.args.get('data'):

            datas = urlparse.parse_qs(self.args.get('data'))

            for param_key, param_value in datas.iteritems():

                self.post_params[param_key] = param_value

                if '*' in param_value:
                    self.post_placeholders.append(param_key)
                    log.warn('Found placeholder in POST parameter \'%s\'' % param_key)

    def _parse_get(self):

        params_dict_list = urlparse.parse_qs(urlparse.urlsplit(self.url).query)

        for param, value_list in params_dict_list.items():
            self.get_params[param] = value_list

            if any(x for x in value_list if '*' in x):
                self.get_placeholders.append(param)
                log.info('Found placeholder in GET parameter \'%s\'' % param)


    def req(self, injection):

        # Inject
        get_params = self.get_params.copy()
        if self.get_placeholders:
            get_placeholder = self.get_placeholders[0]
            get_params[get_placeholder] = injection

        post_params = self.post_params.copy()
        if self.post_placeholders:
            post_placeholder = self.post_placeholders[0]
            post_params[post_placeholder] = injection

        header_params = self.header_params.copy()
        if self.header_placeholders:

            if '\n' in injection:
                log.debug('Skip payload with not compatible character for headers')
            else:
                header_placeholder = self.header_placeholders[0]
                header_params[header_placeholder] = injection

        result = requests.request(
            method = self.http_method,
            url = self.base_url,
            params = get_params,
            data = post_params,
            headers = header_params
            ).text

        log.debug('\n> """%s"""\n< """%s"""' % (injection, result) )

        return result
