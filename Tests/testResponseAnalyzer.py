from Utils.ResponseAnalyzer import ResponseAnalyzer
from Utils.RequestSender import RequestSender
target_url = 'http://127.0.0.2:8011/sqlilabs/Less-2?id='
sender = RequestSender()
response = sender.send_request(target_url)
analyzer = ResponseAnalyzer(response, '././.htaccess')
result = analyzer.is_directory_traversal_vulnerable()
print(result)