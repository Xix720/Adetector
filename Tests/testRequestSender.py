from Utils.RequestSender import RequestSender

testUrl = "http://127.0.0.2:8011/sqlilabs/Less-2/?id=%2Fetc%2Fpopularity-contest.conf"
sender = RequestSender()
response = sender.send_request(testUrl)
print(response.status_code)
print(response.text)
