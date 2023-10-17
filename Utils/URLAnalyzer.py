import urllib.parse


class URLAnalyzer:

    def __init__(self, url):
        self.url = url
        self.parsed_url = urllib.parse.urlparse(url)

    def has_query_params(self):
        return bool(self.parsed_url.query)

    def has_path(self):
        path_segments = self.get_path_segments()
        return len(path_segments) >= 2

    def get_path_segments(self):
        path_segments = self.parsed_url.path.strip('/').split('/')
        return path_segments

    def analyze(self):
        if self.has_query_params():
            return 'has_params'
        elif not self.has_query_params():
            return 'no_params'
        else:
            return 'unknown'
