#!/usr/bin/env python3
from censys_platform import SDK
from censys_platform.utils import BackoffStrategy, RetryConfig
from cortexutils.analyzer import Analyzer


class CensysAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        # Initialization errors are stored and reported by run() through
        # self.error(), so that Cortex always gets a JSON report.
        self.__init_error = None
        self.SDK = None
        self.__per_page = 100
        self.__pages = 200
        self.__truncated = False
        self.__total_hits = None
        try:
            self.__oid = self.get_param(
                "config.oid",
                None,
                "No Organization ID in Censys given. Please add it to the cortex configuration.",
            )
            self.__api_key = self.get_param(
                "config.key",
                None,
                "No API-Key for Censys given. Please add it to the cortex configuration.",
            )
            self.__per_page = int(self.get_param("parameters.max_records", 100))
            self.__pages = int(self.get_param("parameters.pages", 200))
            self.SDK = SDK(
                personal_access_token=self.__api_key,
                organization_id=self.__oid,
                timeout_ms=60000,
                retry_config=RetryConfig(
                    "backoff",
                    BackoffStrategy(1000, 10000, 2.0, 60000),
                    retry_connection_errors=True,
                ),
            )
        except Exception as e:
            self.__init_error = self.__describe_error(e)

    def __describe_error(self, e):
        """Build an error string without leaking the API key or the token."""
        status_code = getattr(e, "status_code", None)
        if status_code is None:
            parts = [repr(e)]
        else:
            parts = [type(e).__name__, f"HTTP status: {status_code}"]
            body = getattr(e, "body", None)
            if body:
                parts.append(f"response body: {str(body)[:2000]}")
        message = "Censys search failed: " + ", ".join(parts)
        for secret in (
            getattr(self, "_CensysAnalyzer__api_key", None),
            getattr(self, "_CensysAnalyzer__oid", None),
        ):
            if secret:
                message = message.replace(str(secret), "***")
        return message

    def search(self, search):
        """
        Searches the Censys Platform and returns the hits

        :param search: Censys Query Language search as string
        :type search: str
        :return: list of hits (dicts)
        """
        sdk_client = self.SDK
        fields = [
            "host.services.port",
            "host.services.protocol",
            "host.services.scan_time",
            "host.ip",
            "host.services.cert.parsed.signature.self_signed",
            "host.services.cert.parsed.issuer.common_name",
            "host.services.cert.parsed.subject.common_name",
            "host.services.cert.validation_level",
            "host.services.cert.names",
            "web.hostname",
            "web.cert.parsed.signature.self_signed",
            "web.cert.parsed.subject.common_name",
            "web.cert.parsed.issuer.common_name",
            "web.cert.names",
            "cert.validated_at",
            "cert.names",
            "cert.parsed.subject_dn",
            "cert.fingerprint_sha1",
            "cert.fingerprint_sha256",
        ]

        with sdk_client as platform:
            page_token = ""
            hits = []
            self.__truncated = False

            for i in range(self.__pages):
                res = platform.global_data.search(
                    search_query_input_body={
                        "query": search,
                        "page_size": self.__per_page,
                        "fields": fields,
                        "page_token": page_token,
                    }
                )

                envelope = getattr(res, "result", None)
                result = getattr(envelope, "result", None)
                if result is None:
                    raise ValueError(
                        "Unexpected Censys response: no result in the response body "
                        f"(response: {res!r:.1000})"
                    )

                # "hits" is nullable in the SDK: it is None when nothing matches
                for elem in result.hits or []:
                    hits.append(elem.model_dump(mode="json"))
                self.__total_hits = result.total_hits
                page_token = result.next_page_token

                if not page_token:
                    break
            else:
                # page limit reached while Censys still has more pages
                self.__truncated = bool(page_token)
            return hits

    def run(self):
        if self.__init_error:
            self.error(self.__init_error)
            return
        try:
            if self.data_type == "other":
                matches = self.search(self.get_data())
                report = {"matches": list(matches), "truncated": self.__truncated}
                if self.__total_hits is not None:
                    report["total_hits"] = self.__total_hits
                self.report(report)
            else:
                self.error(
                    "Data type not supported. Please use this analyzer with data type other."
                )
        except Exception as e:
            self.error(self.__describe_error(e))

    def summary(self, raw):
        taxonomies = []
        if isinstance(raw, dict) and "matches" in raw:
            result_count = len(raw.get("matches") or [])
            level = "suspicious" if raw.get("truncated") else "info"
            taxonomies.append(
                self.build_taxonomy(level, "Censys Platform search", "results", result_count)
            )
            if raw.get("truncated"):
                taxonomies.append(
                    self.build_taxonomy(
                        "info", "Censys Platform search", "truncated", "true"
                    )
                )

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    CensysAnalyzer().run()
