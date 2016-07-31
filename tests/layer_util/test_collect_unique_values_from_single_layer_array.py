from pyshark_parser import pcap_util
from pyshark_parser import layer_util
import tests

layers = pcap_util.aggregate_layer(tests.pcap, 'tcp')
tcp_ports = ['35301', '80', '35302', '80', '35303', '80', '35304', '80', '35305',
             '80', '35306', '80', '35307', '80', '35308', '80', '35309', '80',
             '35310', '80', '35311', '80', '35312', '80', '35313', '80', '35314',
             '80', '35315', '80', '35316', '80', '35317', '80', '35318', '80',
             '35319', '80', '35320', '80', '35321', '80', '35322', '80', '35323',
             '80', '35324', '80', '35325', '80', '35326', '80', '35327', '80',
             '35328', '80', '35329', '80', '35330', '80']

tcp_ports_unique = set(tcp_ports)


class TestCollectUniqueValuesFromSingleLayerArray:
    def test_with_none(self):
        retval = layer_util.collect_unique_values_from_single_layer_array(None)

        assert retval is None

    def test_with_valid_arguments(self):
        layer_array = pcap_util.aggregate_layer(tests.pcap, 'tcp')
        retval = layer_util.collect_unique_values_from_single_layer_array(layer_array)

        assert retval is not None
        assert len(retval['tcp.port']) is len(tcp_ports_unique)
        assert retval['tcp.port'] == tcp_ports_unique
