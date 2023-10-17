from urllib.parse import urlparse
import requests
import scrapy


class ServerTypeSpider(scrapy.Spider):
    name = 'server_type_spider'

    def parse(self, response, **kwargs):
        print(response)
        # 获取服务器类型
        server_type = response.headers.get('Server', 'Unknown')
        print(server_type)
        return server_type
