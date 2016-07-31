from pyshark_parser import pcap_util
from pyshark_parser import packet_util
import tests

packet = tests.first_packet
value = packet.layers[3].__dict__['_all_fields']['http.request.uri']


class TestDiscoverAllFieldsThatMatchValue:
    def test_with_none_for_packet(self):
        retval = packet_util.discover_all_fields_that_match_value(None, value)

        assert retval is None

    def test_with_none_for_value(self):
        retval = packet_util.discover_all_fields_that_match_value(None, value)

        assert retval is None

    def test_with_valid_arguments(self):
        retval = packet_util.discover_all_fields_that_match_value(packet, value)

        assert retval is not None
        assert 'http' in retval
        assert retval['http'] == ['http.request.uri']
