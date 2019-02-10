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
        https_server.socket = ssl.wrap_socket(https_server.socket, certfile=certificate_file, server_side=True)

    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received, exiting...")
        https_server.server_close()
        sys.exit(0)


if __name__ == '__main__':
    # TODO: add start path
    # TODO: add fix for path traversal
    # openssl req -new -x509 -keyout .config/https_upload/server.pem -out .config/https_upload/server.pem -days 365 -nodes -subj "/C=/ST=/O=/OU=/CN="
    if len(sys.argv) < 3:
        print("[-] USAGE: {} <PORT> <USERNAME:PASSWORD> [CERTIFICATE FILE]".format(sys.argv[0]))
        sys.exit(1)

    listening_port = int(sys.argv[1])
    basic_authentication_key = base64.b64encode(sys.argv[2].encode("utf-8"))  # binary
    certificate_file = sys.argv[3] if len(sys.argv) == 4 else False
    print("[+] Staring server...")
    start_https_server(listening_port, basic_authentication_key, certificate_file)
