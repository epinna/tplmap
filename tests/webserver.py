from flask import Flask, request
app = Flask(__name__)
from mako.template import Template as MakoTemplates
from jinja2 import Template as Jinja2Template

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route("/reflect/<engine>")
def reflect(engine):
    
    template = request.values.get('tpl')
    if not template:
        template = '%s'
    
    injection = request.values.get('inj')
    
    if engine == 'mako':
        return MakoTemplates(template % injection).render()
    elif engine == 'jinja2':
        return Jinja2Template(template % injection).render()

@app.route("/post/<engine>", methods = [ "POST" ])
def postfunct(engine):
    
    template = request.values.get('tpl')
    if not template:
        template = '%s'
    
    injection = request.values.get('inj')
    
    if engine == 'mako':
        return MakoTemplates(template % injection).render()
    elif engine == 'jinja2':
        return Jinja2Template(template % injection).render()
            

@app.route('/shutdown')
def shutdown():
    shutdown_server()
    return 'Server shutting down...'

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=15001)