# -*- coding: utf-8 -*-

from collections.abc import Mapping


class ConfigMock:
    def __init__(self, configuration):
        assert isinstance(configuration, Mapping)
        assert all(isinstance(x, Mapping) for x in configuration.values())
        self.configuration = configuration

    def get(self, a, b):
        return self.configuration[a][b]
