from bs4 import BeautifulSoup

# 假设已经有一个HTML文档的字符串内容
html = '''
<html>
<body>
<textarea id="myTextarea"></textarea>
</body>
</html>
'''

# 使用Beautiful Soup解析HTML内容
soup = BeautifulSoup(html, 'html.parser')

# 找到目标textarea标签
textarea_tag = soup.find('textarea', {'id': 'myTextarea'})

# 创建一个新的文本节点，并设置其内容
text_node = soup.new_string('Your specific string')

# 将文本节点插入到目标textarea标签中
textarea_tag.append(text_node)

# 打印修改后的HTML代码
print(soup.prettify())
