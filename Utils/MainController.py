import concurrent.futures
import urllib
from concurrent.futures import ThreadPoolExecutor
from Utils.InputGenerator import InputGenerator
from Utils.RequestSender import RequestSender
from Utils.ResponseAnalyzer import ResponseAnalyzer
from Utils.URLAnalyzer import URLAnalyzer
from Utils.VulnerabilityLogger import VulnerabilityLogger


def test_vulnerability(modified_url, payload, vuln_type):
    sender = RequestSender()
    response = sender.send_request(modified_url)
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
            return vuln_type, modified_url, payload
    return None


class MainController:
    def __init__(self, target_url, dictionaries_path, max_threads=10):
        self.target_url = target_url
        self.dictionaries_path = dictionaries_path
        self.max_threads = max_threads

    def run(self):
        allVul = 0
        vulnerability_results = []
        print("Fuzzing Starting")
        # 构造url结构分析器
        urlAnalyzer = URLAnalyzer(self.target_url)

        # 构造输入生成器
        input_generator = InputGenerator(self.target_url, self.dictionaries_path)

        # 检测目标url中的参数，生成参数列表
        parsed_url = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        print(query_params)
        with ThreadPoolExecutor(self.max_threads) as executor:
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
                    for param in query_params:
                        modified_url2 = input_generator.create_url_with_payload(param, payload)
                        futures.append(executor.submit(test_vulnerability, modified_url2, payload, "path"))

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
        for vul in vulnerability_results:
            vul_str = ', '.join(vul)
            print("Detected vulnerabilities: {}".format(vul_str))
        print("all:")
        print(allVul)
        return vulnerability_results
