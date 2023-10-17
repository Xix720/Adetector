import os
import urllib

import requests
from bs4 import BeautifulSoup

from Utils.URLAnalyzer import URLAnalyzer


class InputGenerator:
    def __init__(self, url, dictionaries_path):
        self.url = url
        self.dictionaries_path = dictionaries_path
        self.xss_payloads = self.load_payloads("Xss_Payloads.txt")
        self.sql_payloads = self.load_payloads("Sql_Payloads.txt")
        self.Dict_payloads = self.load_payloads("path.txt")

    # 从字典文件中读取payload
    def load_payloads(self, file_name):
        file_path = os.path.join(self.dictionaries_path, file_name)
        with open(file_path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f.readlines()]
        return payloads

    # 拼接url和payload
    def create_url_with_payload(self, parameter_name, payload):
        parsed_url = urllib.parse.urlparse(self.url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        print(query_params)

        # 复制查询参数字典
        modified_query_params = query_params.copy()

        # 用 payload 替换给定参数名称的值，确保负载被视为列表
        modified_query_params[parameter_name] = [payload]

        # 使用修复后的查询参数字典
        new_query_string = urllib.parse.urlencode(modified_query_params, doseq=True)
        modified_url = parsed_url._replace(query=new_query_string)

        return modified_url.geturl()

    def create_urls_with_path_payloads(self, payload):
        parsed_url = urllib.parse.urlparse(self.url)
        modified_path = os.path.join(parsed_url.path, payload).replace('\\', '/')
        path_url = parsed_url._replace(path=modified_path)
        modified_url = path_url.geturl()
        return modified_url

    def inject_into_tags(self):
        response = requests.get(self.url)
        html_content = response.text
        # 解析网页，获取其主体
        soup = BeautifulSoup(html_content, 'html.parser')
        # 搜索input标签和textarea标签
        input_tags = soup.find_all('input')




