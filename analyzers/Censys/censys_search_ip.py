#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from censys.ipv4 import CensysIPv4
from censys.base import CensysNotFoundException, CensysRateLimitExceededException, CensysUnauthorizedException


class CensysAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.__uid = self.get_param(
            'config.uid',
            None,
            'No UID for Censys given. Please add it to the cortex configuration.'
        )
        self.__api_key = self.get_param(
            'config.key',
            None,
            'No API-Key for Censys given. Please add it to the cortex configuration.'
        )
        self.__fields = self.get_param(
            'parameters.fields',
            ["updated_at", "ip"]
        )
        self.__max_records = self.get_param(
            'parameters.max_records',
            1000
        )
        self.__flatten = self.get_param(
            'parameters.flatten',
            True
        )

    def search(self, search):
        """
        Searches for hosts in IPv4 base

        :param flatten: If the result is nested or not
        :param max_records: max records to get from censys
        :param search:search as string
        :param censys_fields: fields to get from censys
        :type search: str
        :type max_records: int
        :type censys_fields: list
        :type flatten: bool
        :return: dict
        """
        c = CensysIPv4(api_id=self.__uid, api_secret=self.__api_key)
        return c.search(search, fields=self.__fields,  max_records=self.__max_records, flatten=self.__flatten)

    def run(self):
        try:
            if self.data_type == 'other':
                matches=self.search(self.get_data())
                self.report({
                    'matches': list(matches)
                })
            else:
                self.error('Data type not supported. Please use this analyzer with data types hash, ip or domain.')
        except CensysNotFoundException:
            self.report({
                'message': '{} could not be found.'.format(self.get_data())
            })
        except CensysUnauthorizedException:
            self.error('Censys raised NotAuthorizedException. Please check your credentials.')
        except CensysRateLimitExceededException:
            self.error('Rate limit exceeded.')

    def summary(self, raw):
        taxonomies = []
        if 'matches' in raw:
            result_count = len(raw.get('matches', []))
            taxonomies.append(self.build_taxonomy('info', 'Censys ipv4 search', 'results', result_count))

        return {
            'taxonomies': taxonomies
        }


if __name__ == '__main__':
    CensysAnalyzer().run()
