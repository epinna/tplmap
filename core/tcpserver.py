import socket
from utils.loggers import log
import sys
import select
import threading

class TcpServer:

    def __init__(self, port, timeout):
        self.connect = False
        self.hostname = '0.0.0.0'
        self.port = port

        self.timeout = timeout
        self.socket_state = False

        self.socket = None

        self.connect_socket()

        if not self.socket: return

        log.info("Incoming connection accepted")

        threading.Thread(target=self.receive_data).start()
        self.forward_data()

    def connect_socket(self):
        if(self.connect):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.hostname, self.port))

        else:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,  1)

            try:
                server.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
            except socket.error:
                #log.debug("Warning: unable to set TCP_NODELAY...")
                pass

            try:
                server.bind(('0.0.0.0', self.port))
            except socket.error as e:
                log.error("Port bind on 0.0.0.0:%s has failed: %s" % (self.port, str(e)))
                return

            server.listen(1)

            server.settimeout(self.timeout)

            try:
                self.socket, address = server.accept()
            except socket.timeout as e:
                server.close()
                raise


    def receive_data(self):
        while(1):
            self.socket_state = True
            try:
                data = ''
                while 1:
                    packet = self.socket.recv(1024)
                    data += packet.decode()

                    if len(packet) < 1024:
                        break

                sys.stdout.write(data)
                sys.stdout.flush()
            except socket.error:
                self.socket_state = False


    def forward_data(self):

        self.socket.setblocking(0)

        while(1):
            i = sys.stdin.read(1)
            self.socket.sendall(i.encode())
