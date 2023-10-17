import requests


class RequestSender:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def send_request(self, url, method='GET', headers=None, data=None):
        # 区分请求方式POST和GET，这里默认是GET方式
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=self.timeout)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=data, timeout=self.timeout)
            else:
                raise ValueError("Unsupported HTTP method")
            # 返回响应
            return response
        except requests.exceptions.RequestException as e:
            print(f"Error while sending request: {e}")
            return None
