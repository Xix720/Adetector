from CVE.Components.ApacheHttpServer import cve_vulnerabilities as apache_http_server_vulnerabilities
from CVE.Components.Log4j import cve_vulnerabilities as log4j_vulnerabilities
from CVE.Components.Solr import cve_vulnerabilities as solr_vulnerabilities
from CVE.Components.Struts import cve_vulnerabilities as struts_vulnerabilities


class ComponentsController:

    def __init__(self):
        self.components = {
            'ApacheHttpServer': apache_http_server_vulnerabilities,
            'Log4j': log4j_vulnerabilities,
            'Solr': solr_vulnerabilities,
            'Struts': struts_vulnerabilities
        }

    def check_vulnerabilities(self, component_name, cve_id, *args, **kwargs):
        if component_name in self.components:
            if cve_id in self.components[component_name]:
                return self.components[component_name][cve_id](*args, **kwargs)
            else:
                raise ValueError(f"Unknown CVE ID: {cve_id} for component: {component_name}")
        else:
            raise ValueError(f"Unknown component: {component_name}")

    def check_all_vuls(self, url):
        results = []
        for component_name in self.components:
            for cve_id in self.components[component_name]:
                result = self.check_vulnerabilities(component_name, cve_id, url)
                if result:
                    results.append(component_name+":"+cve_id)
        print(results)
        return results
