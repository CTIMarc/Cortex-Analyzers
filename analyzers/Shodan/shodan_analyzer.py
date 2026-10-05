#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from shodan_api import ShodanAPIPublic
from shodan.exception import APIError


class ShodanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.shodan_key = self.get_param('config.key', None, 'Missing Shodan API key')
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.shodan_client = None


    def encode(self, x):
            if isinstance(x, str):
                return x.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
            elif isinstance(x, dict):
                return {k: self.encode(v) for k, v in x.items()}
            elif isinstance(x, list):
                return [self.encode(k) for k in x]
            else:
                return x

    def execute_shodan_service(self, data):
        if self.service in ['host', 'host_history']:
            results = {'host': self.shodan_client.host(data, history=True if self.service == 'host_history' else False)}
            return results
        elif self.service == 'dns_resolve':
            results = {'records': self.shodan_client.dns_resolve(data)}
            return results
        elif self.service == 'reverse_dns':
            results = {'records': self.shodan_client.reverse_dns(data)}
            return results
        elif self.service == 'search':
            try:
                page = int(self.get_param('parameters.page', 1, None))
            except (TypeError, ValueError):
                self.error("Invalid parameters.page, an integer is expected")
            results = {'records': self.shodan_client.search(data, page)}
            return results
        elif self.service == 'info_domain':
            results = {'info_domain': self.shodan_client.info_domains(data)}
            return results
        else:
            self.error("Unknown service")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        levelorange = "suspicious"
        namespace = "Shodan"
        predicate = "Location"
        if self.service in ['host', 'host_history']:
            host = raw.get('host') or {}
            if 'country_name' in host:
                value = host['country_name']
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            if 'org' in host:
                taxonomies.append(self.build_taxonomy(level, namespace, 'Org', host['org']))
            if 'asn' in host:
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASN', host['asn']))
            if 'vulns' in host:
                totalcve = len(host['vulns'])
                if totalcve < 3: 
                  taxonomies.append(self.build_taxonomy(levelorange, namespace, 'VULNS', host['vulns']))
                else:
                  taxonomies.append(self.build_taxonomy(levelorange, namespace, 'VULNS', totalcve))
        elif self.service == 'info_domain':
            info_domain = raw.get('info_domain') or {}
            if 'ips' in info_domain:
                value = "{}".format(len(info_domain['ips']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'IPs', value))
            if 'all_domains' in info_domain:
                value = "{}".format(len(info_domain['all_domains']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'Domains', value))
            if 'asn' in info_domain:
                value = "{}".format(len(info_domain['asn']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASNs', value))
            if 'isp' in info_domain:
                value = "{}".format(len(info_domain['isp']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ISPs', value))
        elif self.service == 'dns_resolve':
            value = "{}".format(len(raw.get('records') or {}))
            taxonomies.append(self.build_taxonomy(level, namespace, 'DNS resolutions', value))
        elif self.service == 'reverse_dns':
            records = raw.get('records') or {}
            nb_domains = 0
            for k in records.keys():
                nb_domains += len(records[k] or [])
            value = "{}".format(nb_domains)
            taxonomies.append(self.build_taxonomy(level, namespace, 'Reverse DNS resolutions', value))
        elif self.service == 'search':
            value = "{}".format((raw.get('records') or {}).get('total', 0))
            taxonomies.append(self.build_taxonomy(level, namespace, 'Hosts', value))
        return {'taxonomies': taxonomies}

    def run(self):
        try:
            self.shodan_client = ShodanAPIPublic(self.shodan_key)
            data = self.get_param('data', None, 'Data is missing')
            results = self.execute_shodan_service(data)
            self.report(self.encode(results))
                
        except APIError as e:
            self.error(str(e))
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    ShodanAnalyzer().run()
