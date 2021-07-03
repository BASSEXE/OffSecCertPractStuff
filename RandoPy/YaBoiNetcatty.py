import argparse
import shlex
import socket
import subprocess
import threading
import textwrap
import sys

def exe(cmd):
    cmd=cmd.strip()
    if not cmd:
        return
    out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)

    return out.decode()

class NetCatty:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()
    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)
        try:
            while True:
                recv_len = 1
                resp = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    resp += data.decode()
                    if recv_len < 4096:
                        break
                if resp:
                    print(resp)
                    buffer = input('>')
                    buffer += '\n'
                    self.socket.send(buffer.encode())       
        except KeyboardInterrupt:
            print('Session Terminated')
            self.socket.close()
            sys.exit()
    def listen(self):
        print('Listner started')
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _= self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()
    def handle(self, client_socket):
        if self.args.execute:
            out = exe(self.args.exe)
            client_socket.send(out.encode())
        elif self.args.upload:
            file_buffer = b''
            while True:
                dat = client_socket.recv(4096)
                if dat:
                    file_buffer += dat
                    print(len(file_buffer))
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'File {self.args.upload} Saved'
            client_socket.send(message.encode())
        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b' #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    resp = exe(cmd_buffer.decode())
                    if resp:
                        client_socket.send(resp.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'sever session killed Error Message: {e}')
                    self.socket.close()
                    sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description= 'FORTE.EXE | NetCatty',
        formatter_class= argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
        nc.py -t 192.168.1.11 -p 7777 -l -c # cli shell
        nc.py -t 192.168.1.11 -p 7777 -l -u=rockman.exe #file upload
        nc.py -t 192.168.1.11 -p 7777 -l -e=\"sudo -l\" # nc -e 
        echo 'RANDOM TEXT' | ./nc.py -t 192.168.1.11 -p 135 # echo local text to port
        nc.py -t 192.168.11.11 -p 7777 # connect to server
        '''))

parser.add_argument('-c', '--command', action='store_true', help='initialize command shell')
parser.add_argument('-u', '--upload', help='upload file')
parser.add_argument('-e', '--execute', help='execute specified command')
parser.add_argument('-l', '--listen', action='store_true', help='listen')
parser.add_argument('-p', '--port', type=int, default=7777, help='specified port')
parser.add_argument('-t', '--target', default='127.0.0.1', help='Target IP address')
args = parser.parse_args()
## this that der listner put that der empty buffer mhmm
if args.listen:
    buffer = ''
else:
    buffer = sys.stdin.read()

nc = NetCatty(args, buffer.encode('utf-8'))
nc.run()






