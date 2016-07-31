from pyshark_parser import pcap_util
from pyshark_parser import packet_util
import tests

packet = tests.first_packet
value = '20'

http = ['_ws.expert.group', '_ws.expert.severity']
ip = ['ip.dst_host', 'ip.src_host', 'ip.hdr_len', 'ip.dst', 'ip.host', 'ip.addr', 'ip.src']


class TestDiscoverAllFieldsThatContainValue:
    def test_with_none_for_packet(self):
        retval = packet_util.discover_all_fields_that_contain_value(None, value)

        assert retval is None

    def test_with_none_for_value(self):
        retval = packet_util.discover_all_fields_that_contain_value(None, value)

        assert retval is None

    def test_with_valid_arguments(self):
        retval = packet_util.discover_all_fields_that_contain_value(packet, value)

        assert retval is not None
        assert 'http' in retval
        assert 'ip' in retval
        assert retval['http'] == http
        assert retval['ip'] == ip
