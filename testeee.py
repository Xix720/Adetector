import concurrent
import urllib
from concurrent.futures import ThreadPoolExecutor
from Utils.RequestSender import RequestSender
from Utils.ResponseAnalyzer import ResponseAnalyzer
from Utils.VulnerabilityLogger import VulnerabilityLogger
from Utils.InputGenerator import InputGenerator
from Utils.URLAnalyzer import URLAnalyzer

max_threads = 10
vulnerability_results = []
target_url = 'http://127.0.0.2:8011/sqlilabs/Less-1/?id=2'
dictionaries_path = "Dictionaries"
allVul = 0
sql = 0
xss = 0
path = 0
print("Fuzzing Starting")
# 构造url结构分析器
urlAnalyzer = URLAnalyzer(target_url)

# 构造输入生成器
input_generator = InputGenerator(target_url, dictionaries_path)
vulnerabilities = []

# 检测目标url中的参数，生成参数列表
parsed_url = urllib.parse.urlparse(target_url)
query_params = urllib.parse.parse_qs(parsed_url.query)
print(query_params)


def test_vulnerability(modified_url, payload, vuln_type):
    sender = RequestSender()
    response = sender.send_request(modified_url)
    print(modified_url)
    print(response.status_code)
    if response:
        analyzer = ResponseAnalyzer(response, payload)
        if vuln_type == "xss":
            vulnerable = analyzer.is_xss_vulnerable()
        elif vuln_type == "sql_injection":
            vulnerable = analyzer.is_sql_injection_vulnerable()
        elif vuln_type == "path":
            vulnerable = analyzer.is_directory_traversal_vulnerable()
        else:
            raise ValueError("Invalid vulnerability type")

        if vulnerable:
            # log_file = "./Log/log1.txt"
            # logger = VulnerabilityLogger(log_file)
            # logger.log_warning(f"{vuln_type.upper()} vulnerability detected for payload: {payload}")
            return modified_url, payload
    return None


with ThreadPoolExecutor(max_threads) as executor:
    futures = []
    if urlAnalyzer.analyze() == 'has_params':
        for payload in input_generator.xss_payloads:
            for param in query_params:
                modified_url = input_generator.create_url_with_payload(param, payload)
                futures.append(executor.submit(test_vulnerability, modified_url, payload, "xss"))

        for payload in input_generator.sql_payloads:
            for param in query_params:
                modified_url = input_generator.create_url_with_payload(param, payload)
                futures.append(executor.submit(test_vulnerability, modified_url, payload, "sql_injection"))

        for payload in input_generator.Dict_payloads:
            modified_url = input_generator.create_urls_with_path_payloads(payload)
            futures.append(executor.submit(test_vulnerability, modified_url, payload, "path"))
            # if test_vulnerability(modified_url, payload, "path"):
            #     path += 1
            # for param in query_params:
            #     modified_url2 = input_generator.create_url_with_payload(param, payload)
            #     futures.append(executor.submit(test_vulnerability, modified_url2, payload, "path"))
            # if test_vulnerability(modified_url2, payload, "path"):
            #     path += 1

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                vulnerability_results.append(result)
                allVul += 1
    elif urlAnalyzer.analyze() == 'no_params':
        for payload in input_generator.Dict_payloads:
            modified_url = input_generator.create_urls_with_path_payloads(payload)
            futures.append(executor.submit(test_vulnerability, modified_url, payload, "path"))

            for param in query_params:
                modified_url2 = input_generator.create_url_with_payload(param, payload)
                futures.append(executor.submit(test_vulnerability, modified_url2, payload, "path"))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                vulnerability_results.append(result)
                allVul += 1

print(len(vulnerability_results))
print("Detected vulnerabilities:", vulnerability_results)
print("all:")
print(allVul)
print("xss:")
print(xss)
print("sql:")
print(sql)
print("path:")
print(path)
print(len(futures))
