import requests
from bs4 import BeautifulSoup

# 发送请求获取网页内容
url = "http://127.0.0.2:8011/sqlilabs/Less-1/?id='1<svg onload=alert(1)>"
response = requests.get(url)
html_content = response.text

# 构造XSS payload
xss_payload = "'1<svg onload=alert(1)>"

# 解析HTML内容
soup = BeautifulSoup(html_content, 'html.parser')


def check_xss_vulnerability(element, payloads):
    if element.string and any(payload in element.string for payload in payloads):
        return True
    if element.attrs and any(payload in value for value in element.attrs.values() for payload in payloads):
        return True
    for child in element.children:
        if isinstance(child, str):
            continue
        if check_xss_vulnerability(child, payloads):
            return True
    return False


# 检查XSS漏洞
result = check_xss_vulnerability(soup, xss_payload)
print(result)
