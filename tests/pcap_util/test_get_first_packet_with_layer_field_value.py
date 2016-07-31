from pyshark_parser import pcap_util
import tests


class TestGetFirstPacketWithLayerFieldValue:
    def test_with_none_for_pcap(self):
        retval = pcap_util.get_first_packet_with_layer_field_value(None,
                                                                   'tcp',
                                                                   'tcp.srcport',
                                                                   '35301')

        assert retval is None

    def test_with_none_for_layer(self):
        retval = pcap_util.get_first_packet_with_layer_field_value(tests.pcap,
                                                                   None,
                                                                   'tcp.srcport',
                                                                   '35301')

        assert retval is None

    def test_with_none_for_field(self):
        retval = pcap_util.get_first_packet_with_layer_field_value(tests.pcap,
                                                                   'tcp',
                                                                   None,
                                                                   '35301')

        assert retval is None

    def test_with_none_for_value(self):
        retval = pcap_util.get_first_packet_with_layer_field_value(tests.pcap,
                                                                   'tcp',
                                                                   'tcp.srcport',
                                                                   None)

        assert retval is None

    def test_with_valid_arguments(self):
        '''
            These are kinda crappy/biased tests, but I know I iterate through
            the pcap packets and return the first found.

            The more important tests, to me, are the ones where I handle edge cases.
        '''
        retval = pcap_util.get_first_packet_with_layer_field_value(tests.pcap,
                                                                   'tcp',
                                                                   'tcp.srcport',
                                                                   '35301')

        assert retval is not None
