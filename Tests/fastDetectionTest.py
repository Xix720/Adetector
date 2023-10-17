from CVE.Components import Log4j

test_url = "https://blog.51cto.com/topic/log4jshiyongfangfa.html"
result = Log4j.check_cve_2017_5645(test_url)
print(result)