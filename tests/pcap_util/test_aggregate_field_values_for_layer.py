from pyshark_parser import pcap_util
import tests


tcp_ports = ['35301', '80', '35302', '80', '35303', '80', '35304', '80', '35305',
             '80', '35306', '80', '35307', '80', '35308', '80', '35309', '80',
             '35310', '80', '35311', '80', '35312', '80', '35313', '80', '35314',
             '80', '35315', '80', '35316', '80', '35317', '80', '35318', '80',
             '35319', '80', '35320', '80', '35321', '80', '35322', '80', '35323',
             '80', '35324', '80', '35325', '80', '35326', '80', '35327', '80',
             '35328', '80', '35329', '80', '35330', '80']

tcp_ports_unique = set(tcp_ports)


class TestAggregateFieldValuesForLayer:
    def test_with_none_for_pcap(self):
        retval = pcap_util.aggregate_field_values_for_layer(None,
                                                            'http')

        assert retval is None

    def test_with_none_for_layer(self):
        retval = pcap_util.aggregate_field_values_for_layer(None,
                                                            'http')

        assert retval is None

    def test_with_valid_arguments(self):
        retval = pcap_util.aggregate_field_values_for_layer(tests.pcap,
                                                            'tcp',
                                                            False)

        assert retval is not None
        assert len(retval['tcp.port']) is len(tcp_ports)
        assert retval['tcp.port'] == tcp_ports

        retval = pcap_util.aggregate_field_values_for_layer(tests.pcap,
                                                            'tcp',
                                                            True)

        assert retval is not None
        assert len(retval['tcp.port']) is len(tcp_ports_unique)
        assert retval['tcp.port'] == tcp_ports_unique
