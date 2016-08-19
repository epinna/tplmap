var connect = require('connect');
var http = require('http');
var url = require('url');
var jade = require('jade');
var nunjucks = require('nunjucks');

var app = connect();

// respond to all requests
app.use('/jade', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);

    var inj = url_parts.query.inj;
    var tpl = '';
    if('tpl' in url_parts.query) {
      // Keep the formatting a-la-python
      tpl = url_parts.query.tpl.replace('%s', inj);
    }
    else {
      tpl = inj;
    }
    res.end(jade.render(tpl));
  }
});

// blind endpoint
app.use('/blind/jade', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);

    var inj = url_parts.query.inj;
    var tpl = '';
    if('tpl' in url_parts.query) {
      // Keep the formatting a-la-python
      tpl = url_parts.query.tpl.replace('%s', inj);
    }
    else {
      tpl = inj;
    }
    jade.render(tpl)
    res.end();
  }
});

// respond to all requests
app.use('/nunjucks', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);

    var inj = url_parts.query.inj;
    var tpl = '';
    if('tpl' in url_parts.query) {
      // Keep the formatting a-la-python
      tpl = url_parts.query.tpl.replace('%s', inj);
    }
    else {
      tpl = inj;
    }
    res.end(nunjucks.renderString(tpl));
  }
});

// blind endpoint
app.use('/blind/nunjucks', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);

    var inj = url_parts.query.inj;
    var tpl = '';
    if('tpl' in url_parts.query) {
      // Keep the formatting a-la-python
      tpl = url_parts.query.tpl.replace('%s', inj);
    }
    else {
      tpl = inj;
    }
    nunjucks.renderString(tpl);
    res.end();
  }
});

// respond to all requests
app.use('/javascript', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);

    var inj = url_parts.query.inj;
    var tpl = '';
    if('tpl' in url_parts.query) {
      // Keep the formatting a-la-python
      tpl = url_parts.query.tpl.replace('%s', inj);
    }
    else {
      tpl = inj;
    }
    res.end(JSON.stringify(eval(tpl)));
  }
});

// blind endpoint
app.use('/blind/javascript', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);

    var inj = url_parts.query.inj;
    var tpl = '';
    if('tpl' in url_parts.query) {
      // Keep the formatting a-la-python
      tpl = url_parts.query.tpl.replace('%s', inj);
    }
    else {
      tpl = inj;
    }
    eval(tpl);
    res.end();
  }
});

//create node.js http server and listen on port
http.createServer(app).listen(15004);
