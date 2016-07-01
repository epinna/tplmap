from flask import Flask, request
app = Flask(__name__)
from mako.template import Template

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route("/reflect")
def reflect():
    
    template = request.values.get('tpl')
    if not template:
        template = '%s'
    
    injection = request.values.get('inj')
    
    return Template(template % injection).render()

@app.route('/shutdown')
def shutdown():
    shutdown_server()
    return 'Server shutting down...'

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=15001)