#!/usr/bin/env python3

import base64
import os
import re
import shutil
import sys
import urllib

import cgi
import http.server
import ssl


class CustomBaseHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    # Replace server headers from "Server: BaseHTTP/0.6 Python/3.6.7"
    server_version = "Microsoft-HTTPAPI/2.0"  # replaces BaseHTTP/0.6
    sys_version = ""  # replaces Python/3.6.7


    def is_authenticated(self):
        authorization_header = self.headers["Authorization"]

        if authorization_header != self.basic_authentication_key:
            self.do_AUTHHEAD()
            self.close_connection = True
            return False

        return True


    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Basic realm=\"Test\"")
        self.send_header("Content-type", "text/html")
        self.end_headers()


    def do_HEAD(self):
        return self.do_GETANDHEAD()


    def do_GET(self):
        return self.do_GETANDHEAD()


    def do_POST(self):
        if not self.is_authenticated():
            return self.do_GET()

        post_form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers['Content-Type']
            }
        )

        dir_path = os.path.dirname(os.path.realpath(__file__))
        file_name = urllib.parse.unquote(post_form["file"].filename)

        with open(dir_path + self.path + file_name, 'wb') as file_object:
            shutil.copyfileobj(post_form["file"].file, file_object)

        return self.do_GET()


    def do_GETANDHEAD(self):
        if not self.is_authenticated():
            return

        request_path = os.getcwd() + re.split(r'\?|\#', self.path)[0]

        if os.path.isdir(request_path):
            directory_contents_html = self.get_directory_contents_html(request_path)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(directory_contents_html)))
            self.end_headers()
            self.wfile.write(directory_contents_html)

            return

        try:
            request_path = urllib.parse.unquote(request_path)

            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-Length", str(os.stat(request_path).st_size))
            self.send_header("Last-Modified", self.date_time_string(os.stat(request_path).st_mtime))
            self.end_headers()

            if self.command == "GET":
                request_file = open(request_path, 'rb')

                shutil.copyfileobj(request_file, self.wfile)

                request_file.close()
        except IOError:
            self.send_error(404, "File not found")
            return

        return


    def get_directory_contents_html(self, request_path):
        # TODO: change design
        # TODO: change header path
        try:
            file_list = os.listdir(request_path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return ""

        file_list_html = ""
        for file_name in file_list:
            file_href = file_display_name = file_name

            if os.path.isdir(file_name):
                file_display_name = file_name + "/"
                file_href = file_href + "/"
            if os.path.islink(file_name):
                file_display_name = file_name + "@"

            file_list_html = file_list_html + "<li><a href=\"{}\">{}</a></li>\n".format(
                urllib.parse.quote(file_href), file_display_name
            )

        return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Microsoft-HTTPAPI/2.0</title>
                <link href="data:image/x-icon;base64,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" rel="icon" type="image/x-icon" />
            </head>
            <body>
                <h2>Directory listing for {}</h2>
                <hr>
                <form ENCTYPE="multipart/form-data" method="post">
                    <input name="file" type="file"/>
                    <input type="submit" value="upload"/>
                </form>
                <hr>
                <ul>
                    {}
                </ul>
                <hr>
            </body>
            </html>
        """.format(request_path, file_list_html).encode()


def start_https_server(listening_port, basic_authentication_key, certificate_file):
    CustomBaseHTTPRequestHandler.basic_authentication_key = "Basic " + basic_authentication_key.decode("utf-8")

    https_server = http.server.HTTPServer(("0.0.0.0", listening_port), CustomBaseHTTPRequestHandler)
    if certificate_file:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=certificate_file)

        https_server.socket = ssl_context.wrap_socket(https_server.socket, server_side=True)

    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received, exiting...")
        https_server.server_close()
        sys.exit(0)


if __name__ == '__main__':
    # TODO: add start path
    # TODO: add fix for path traversal
    # openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/C=/ST=/O=/OU=/CN="
    if len(sys.argv) < 3:
        print("[-] USAGE: {} <PORT> <USERNAME:PASSWORD> [CERTIFICATE FILE]".format(sys.argv[0]))
        sys.exit(1)

    listening_port = int(sys.argv[1])
    basic_authentication_key = base64.b64encode(sys.argv[2].encode("utf-8"))  # binary
    certificate_file = sys.argv[3] if len(sys.argv) == 4 else False
    print("[+] Staring server...")
    start_https_server(listening_port, basic_authentication_key, certificate_file)
