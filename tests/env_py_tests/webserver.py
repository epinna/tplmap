from flask import Flask, request
app = Flask(__name__)
from mako.template import Template as MakoTemplates
from mako.lookup import TemplateLookup
from jinja2 import Environment as Jinja2Environment
import tornado.template
import random
import string

mylookup = TemplateLookup(directories=['/tpl'])

Jinja2Env = Jinja2Environment(line_statement_prefix='#')

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

def randomword(length = 8):
   return ''.join(random.choice(string.lowercase) for i in range(length))

@app.route("/reflect/<engine>")
def reflect(engine):

    template = request.values.get('tpl')
    if not template:
        template = '%s'

    injection = request.values.get('inj')

    if engine == 'mako':
        return randomword() + MakoTemplates(template % injection, lookup=mylookup).render() + randomword()
    elif engine == 'jinja2':
        return randomword() + Jinja2Env.from_string(template % injection).render() + randomword()
    elif engine == 'eval':
        return randomword() + str(eval(template % injection)) + randomword()
    elif engine == 'tornado':
        return randomword() + tornado.template.Template(template % injection).generate() + randomword()

@app.route("/post/<engine>", methods = [ "POST" ])
def postfunc(engine):

    template = request.values.get('tpl')
    if not template:
        template = '%s'

    injection = request.values.get('inj')

    if engine == 'mako':
        return randomword() + MakoTemplates(template % injection, lookup=mylookup).render() + randomword()
    elif engine == 'jinja2':
        return randomword() + Jinja2Env.from_string(template % injection).render() + randomword()


@app.route("/header/<engine>")
def headerfunc(engine):

    template = request.headers.get('tpl')
    if not template:
        template = '%s'

    injection = request.headers.get('User-Agent')

    if engine == 'mako':
        return randomword() + MakoTemplates(template % injection, lookup=mylookup).render() + randomword()
    elif engine == 'jinja2':
        return randomword() + Jinja2Env.from_string(template % injection).render() + randomword()

@app.route("/put/<engine>", methods = [ "PUT" ])
def putfunc(engine):

    template = request.values.get('tpl')
    if not template:
        template = '%s'

    injection = request.values.get('inj')
    if engine == 'mako':
        return randomword() + MakoTemplates(template % injection, lookup=mylookup).render() + randomword()
    elif engine == 'jinja2':
        return randomword() + Jinja2Env.from_string(template % injection).render() + randomword()

@app.route("/limit/<engine>")
def limited(engine):
    template = request.values.get('tpl')
    if not template:
        template = '%s'

    length = int(request.values.get('limit'))

    injection = request.values.get('inj', '')
    if len(injection) > length:
        return 'Inj too long'

    if engine == 'mako':
        return randomword() + MakoTemplates(template % injection, lookup=mylookup).render() + randomword()
    elif engine == 'jinja2':
        return randomword() + Jinja2Env.from_string(template % injection).render() + randomword()

@app.route("/startswith/<engine>")
def startswithtest(engine):
    template = request.values.get('tpl')
    if not template:
        template = '%s'

    str_startswith = request.values.get('startswith')

    injection = request.values.get('inj', '')
    if not injection.startswith(str_startswith):
        return 'Missing startswith'

    if engine == 'mako':
        return randomword() + MakoTemplates(template % injection, lookup=mylookup).render() + randomword()
    elif engine == 'jinja2':
        return randomword() + Jinja2Env.from_string(template % injection).render() + randomword()


@app.route("/blind/<engine>")
def blind(engine):

    template = request.values.get('tpl')
    if not template:
        template = '%s'

    injection = request.values.get('inj')

    if engine == 'mako':
        MakoTemplates(template % injection, lookup=mylookup).render()
    elif engine == 'jinja2':
        Jinja2Env.from_string(template % injection).render()
    elif engine == 'eval':
        eval(template % injection)
    elif engine == 'tornado':
        tornado.template.Template(template % injection).generate()
        
    return randomword()

@app.route('/shutdown')
def shutdown():
    shutdown_server()
    return 'Server shutting down...'

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=15001, debug=False)
