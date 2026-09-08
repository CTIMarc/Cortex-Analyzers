#!/usr/bin/env python3
# encoding: utf-8

import json
import re

import requests
from cortexutils.analyzer import Analyzer


class CurstomProxy(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.base_url = self.get_param(
            "config.base_url",
            None,
            "No base URL configuration in Cortex.",
        )
        # the request url is built by plain concatenation below, so tolerate a
        # base url configured without its trailing slash
        if not self.base_url.endswith("/"):
            self.base_url += "/"

    def do_request(self, method, module, url, headers, post_data, post_data_hex):
        try:
            if method == "GET":
                req = requests.get(
                    self.base_url + module + "/" + url, headers=headers, timeout=30
                )
                req.raise_for_status()
            elif method == "POST":
                if post_data:
                    data = post_data
                elif post_data_hex:
                    data = bytes.fromhex(post_data_hex)
                req = requests.post(
                    self.base_url + module + "/" + url,
                    headers=headers,
                    data=data,
                    timeout=30,
                )
                req.raise_for_status()
            elif method == "OPTIONS":
                req = requests.options(
                    self.base_url + module + "/" + url, headers=headers, timeout=30
                )
                req.raise_for_status()
            else:
                self.error("Unknown method")
        except Exception as e:
            self.error(
                f"Error trying to contact {self.base_url + module + '/' + url}: {repr(e)}"
            )
        else:
            try:
                to_check = req.json()
            except requests.exceptions.JSONDecodeError as e:
                to_check = req.content.decode()
            results = to_check
            return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "CustomProxy"

        value = "{}".format(raw["status"])
        taxonomies.append(self.build_taxonomy(level, namespace, "Status_Code", value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        try:
            method = self.get_param("parameters.method", default="GET")
            module = self.get_param("parameters.module", default="get-tor")
            url = self.get_param("data", None, "Data param is missing")
            headers = self.get_param("parameters.headers", default={})
            post_data = self.get_param("parameters.post_data", default={})
            post_data_hex = self.get_param("parameters.post_data_hex", default={})
            self.report(
                self.do_request(method, module, url, headers, post_data, post_data_hex)
            )
        except Exception as e:
            self.unexpectedError(e)


if __name__ == "__main__":
    CurstomProxy().run()
