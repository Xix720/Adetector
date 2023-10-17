from Utils.URLAnalyzer import URLAnalyzer
# 只有路径的情况
testURL1 = 'https://aon.design/grenada_portfolio/ececera/'
url_analyzer = URLAnalyzer(testURL1)
url_structure = url_analyzer.analyze()
print('testURL1:'+testURL1+'\n'+url_structure)

# 只有参数的情况
testURL2 = 'https://www.baidu.com/?tn=21002492_9_hao_pg'
url_analyzer = URLAnalyzer(testURL2)
url_structure = url_analyzer.analyze()
print('testURL2:'+testURL2+'\n'+url_structure)

# 既有路径也有参数的情况
testURL3 = 'https://example.com/products/electronics/computers?brand=apple&color=space_gray'
url_analyzer = URLAnalyzer(testURL3)
url_structure = url_analyzer.analyze()
print('testURL3:'+testURL3+'\n'+url_structure)

if url_structure == 'query_params':
    # 调用针对查询参数的测试方法
    pass
elif url_structure == 'path':
    # 调用针对路径的测试方法
    pass
else:
    # 调用针对其他URL结构的测试方法
    pass
