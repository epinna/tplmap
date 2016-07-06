var connect = require('connect');
var http = require('http');
var url = require('url');
var jade = require('jade');
 
var app = connect();
 
// respond to all requests 
app.use('/jade', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);
    if('inj' in url_parts.query) {
      res.end(jade.render(url_parts.query.inj));  
    }
    res.end();
  }
});
 
//create node.js http server and listen on port 
http.createServer(app).listen(15004);