#!/usr/bin/env python3
# encoding: utf-8

import time
import hashlib
import requests
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from cortexutils.analyzer import Analyzer
import urllib.parse


class VirusTotalAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.virustotal_key = self.get_param('config.key', None, 'Missing VirusTotal API key')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.proxies = self.get_param('config.proxy', None)
        self.vt = VirusTotalPublicApi(self.virustotal_key, self.proxies)

    def wait_file_report(self, id):
        results = self.check_response(self.vt.get_file_report(id))
        code = results.get('response_code', None)
        if code == 1:
            self.report(results)
        else:
            time.sleep(self.polling_interval)
            self.wait_file_report(id)

    def wait_url_report(self, id):
        results = self.check_response(self.vt.get_url_report(id))
        code = results.get('response_code', None)
        if code == 1 and (results.get('scan_id') == id):
            self.report(results)
        else:
            time.sleep(self.polling_interval)
            self.wait_url_report(id)

    def check_response(self, response):
        if type(response) is not dict:
            self.error('Bad response : ' + str(response))
        status = response.get('response_code', -1)
        if status == 204:
            self.error('VirusTotal api rate limit exceeded (Status 204).')
        if status != 200:
            self.error('Bad status : ' + str(status))
        results = response.get('results', {})
        if 'Missing IP address' in results.get('verbose_msg', ''):
            results['verbose_msg'] = 'IP address not available in VirusTotal'
        return results

        # 0 => not found
        # -2 => in queue
        # 1 => ready

    def read_scan_response(self, response, func):
        results = self.check_response(response)
        code = results.get('response_code', None)
        scan_id = results.get('scan_id', None)
        if code == 1 and scan_id is not None:
            func(scan_id)
        else:
            self.error('Scan not found')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "VT"
        predicate = "GetReport"
        value = "0"

        if self.service == "scan":
            predicate = "Scan"
        if self.service != 'search' and self.service!='relationships':
            result = {
                "has_result": True
            }

            if raw["response_code"] != 1:
                result["has_result"] = False

            result["positives"] = raw.get("positives", 0)
            result["total"] = raw.get("total", 0)

        if "scan_date" in raw:
            result["scan_date"] = raw["scan_date"]

        if self.service == "get":
            if "scans" in raw:
                result["scans"] = len(raw["scans"])
                value = "{}/{}".format(result["positives"], result["total"])
                if result["positives"] == 0:
                    level = "safe"
                elif result["positives"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

            if "resolutions" in raw:
                result["resolutions"] = len(raw["resolutions"])
                value = "{} resolution(s)".format(result["resolutions"])
                if result["resolutions"] == 0:
                    level = "safe"
                elif result["resolutions"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"
            if "detected_urls" in raw:
                result["detected_urls"] = len(raw["detected_urls"])
                value = "{} detected_url(s)".format(result["detected_urls"])
                if result["detected_urls"] == 0:
                    level = "safe"
                elif result["detected_urls"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

            if "detected_downloaded_samples" in raw:
                result["detected_downloaded_samples"] = len(
                    raw["detected_downloaded_samples"])

        if self.service == "scan":
            if "scans" in raw:
                result["scans"] = len(raw["scans"])
                value = "{}/{}".format(result["positives"], result["total"])
                if result["positives"] == 0:
                    level = "safe"
                elif result["positives"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

        if self.service == 'search':
            predicate = "search"
            if 'meta' in raw and 'total_hits' in raw["meta"]:
                value = "{}".format(raw["meta"]["total_hits"])
            else:
                value = "{}".format(0)

        if self.service == 'relationships':
            predicate = "relationships"
            print(raw["meta"])
            if 'meta' in raw and 'count' in raw["meta"]:
                value = "{}".format(raw["meta"]["count"])
            else:
                value = "{}".format(0)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}


    def run(self):
        if self.service == 'scan':
            if self.data_type == 'file':
                filename = self.get_param('filename', 'noname.ext')
                filepath = self.get_param('file', None, 'File is missing')
                self.read_scan_response(
                    self.vt.scan_file(filepath, from_disk=True, filename=filename),
                    self.wait_file_report
                )
            elif self.data_type == 'url':
                data = self.get_param('data', None, 'Data is missing')
                self.read_scan_response(
                    self.vt.scan_url(data), self.wait_url_report)
            else:
                self.error('Invalid data type')
        elif self.service == 'get':
            if self.data_type == 'domain':
                data = self.get_param('data', None, 'Data is missing')
                self.report(self.check_response(
                    self.vt.get_domain_report(data)))
            elif self.data_type == 'ip':
                data = self.get_param('data', None, 'Data is missing')
                self.report(self.check_response(self.vt.get_ip_report(data)))
            elif self.data_type == 'file':
                hashes = self.get_param('attachment.hashes', None)
                if hashes is None:
                    filepath = self.get_param('file', None, 'File is missing')
                    hash = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
                else:
                    # find SHA256 hash
                    hash = next(h for h in hashes if len(h) == 64)

                self.report(self.check_response(self.vt.get_file_report(hash)))
            elif self.data_type == 'hash':
                data = self.get_param('data', None, 'Data is missing')
                self.report(self.check_response(self.vt.get_file_report(data)))
            elif self.data_type == 'url':
                data = self.get_param('data', None, 'Data is missing')
                self.report(self.check_response(self.vt.get_url_report(data)))
            else:
                self.error('Invalid data type')
        elif self.service == 'search':
            # documentation https://developers.virustotal.com/reference/intelligence-search
            limit = self.get_param('parameters.limit', 20)
            cursor = self.get_param('parameters.cursor',None)
            data = urllib.parse.quote_plus(self.get_data())
            if cursor:
                url = f"""https://www.virustotal.com/api/v3/intelligence/search?cursor={cursor}&limit={str(limit)}&query={data}"""
            else:
                url = f"""https://www.virustotal.com/api/v3/intelligence/search?limit={str(limit)}&query={data}"""
            headers = {
                        "Accept": "application/json",
                        "X-Apikey": self.virustotal_key
                        }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                self.report(json.loads(response.text))
            elif response.status_code == 429:
                # quota exceeded
                self.error('Quota Exceeded')
            else:
                self.error(f'Error throw by VT, status code: {str(response.status_code)}')
        elif self.service == 'relationships':
            limit = self.get_param('parameters.limit', 20)
            cursor = self.get_param('parameters.cursor', None)
            relationship = self.get_param('parameters.relationship',"itw_urls") #default value set to "itw_urls" to avoid errors.
            data = self.get_data()
            if cursor:
                url = f"""https://www.virustotal.com/api/v3/files/{data}/{relationship}?limit={limit}&cursor={cursor}"""
            else:
                url = f"""https://www.virustotal.com/api/v3/files/{data}/{relationship}"""
            headers = {
                        "Accept": "application/json",
                        "X-Apikey": self.virustotal_key
                        }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                self.report(json.loads(response.text))
            elif response.status_code == 429:
                # quota exceeded
                self.error('Quota Exceeded')
            else:
                self.error(f'Error throw by VT, status code: {str(response.status_code)}')

        else:
            self.error('Invalid service')


if __name__ == '__main__':
    VirusTotalAnalyzer().run()
