import urllib.parse

from Utils.InputGenerator import InputGenerator

# 只有一个参数的情况
testUrl1 = 'http://www.test.com?testparam1=1'
# 有多个参数的情况
testUrl2 = 'http://www.test.com?testparam1=1&testparam2=2'
# 无参数情况
testUrl3 = 'http://www.test.com'

# 检测目标url中的参数，生成参数列表
parsed_url = urllib.parse.urlparse(testUrl2)
query_params = urllib.parse.parse_qs(parsed_url.query)
print("params in this url are:")
print(query_params)

dictPath = '../Dictionaries'
generator = InputGenerator(testUrl3, dictPath)
# 有参数情况测试
# for payload in generator.xss_payloads:
#     for param in query_params:
#         modified_url = generator.create_url_with_payload(param, payload)
#         print("with payload:"+payload+"created modified url:"+modified_url+"\n")

# 无参数情况测试
for payload in generator.Dict_payloads:
    modified_url = generator.create_urls_with_path_payloads(payload)
    print(modified_url)
