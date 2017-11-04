import http.server
import ssl


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        varLen = int(self.headers['Content-Length'])
        self.server.postVars = self.rfile.read(varLen)
        print(self.server.postVars)
        file = open("testfile.txt", "w")
        file.write(self.server.postVars.decode().replace('&', '\n'))


port = 3050

httpd = http.server.HTTPServer(('localhost', port), MyHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='privkeyA.pem', certfile='certA.crt', server_side=True)
print("serving at port", port)
httpd.serve_forever()

# python server.py
# https://localhost:3050/
