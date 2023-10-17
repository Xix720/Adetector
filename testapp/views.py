import json
from urllib.parse import urlparse
from django.http import JsonResponse
import requests
from django.shortcuts import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from Utils.ServerSpider import ServerTypeSpider
from CVE.CompController import ComponentsController
from Utils.MainController import MainController


# Create your views here.
@csrf_exempt
def fingerprint_rec(request):
    url = json.loads(request.body)
    print(url)
    netloc = urlparse(url).netloc
    if netloc:
        # 发送HTTP请求并获取响应
        response = requests.get(url)
        # 使用爬虫类爬取Url指纹数据
        spider = ServerTypeSpider()
        server_type = spider.parse(response)
        print(server_type)
        if 'Apache' in server_type or 'apache' in server_type:
            Apache_used = 'Yes'
        else:
            Apache_used = 'No'
        return HttpResponse(Apache_used)


@csrf_exempt
def fast_detection(request):
    url = json.loads(request.body)
    print(url)
    controller = ComponentsController()
    result = controller.check_all_vuls(url)
    formatted_vul_list = [
        {"type": "CVE", "id": vul_name, "payload": "无", "severity": "高"} for vul_name in result
    ]

    print(formatted_vul_list)
    return JsonResponse(formatted_vul_list, safe=False)


@csrf_exempt
def fuzz_testing(request):
    dictionaries_path = "Dictionaries"
    max_threads = 10
    # 获取url
    target_url = json.loads(request.body)

    print(target_url)
    controller = MainController(target_url, dictionaries_path, max_threads)
    vulnerabilities = controller.run()
    for vul in vulnerabilities:
        print(vul)
    formatted_list = [
        {"type": vul[0], "id": "无", "payload": vul[2], "severity": "高"}
        for vul in vulnerabilities
    ]
    return JsonResponse(formatted_list,  safe=False)
