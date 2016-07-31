from pyshark_parser import pcap_util
import tests


class TestSplitPacketsBaseOnPresenceOfField:
    def test_with_none_for_pcap(self):
        retval = pcap_util.split_packets_based_on_presence_of_field(None,
                                                                    'http',
                                                                    'http.request.uri')

        assert retval is None

    def test_with_none_for_value(self):
        retval = pcap_util.split_packets_based_on_presence_of_field(tests.pcap,
                                                                    None,
                                                                    'http.request.uri')

        assert retval is None

    def test_with_none_for_value(self):
        retval = pcap_util.split_packets_based_on_presence_of_field(tests.pcap,
                                                                    'http',
                                                                    None)

        assert retval is None

    def test_with_valid_arguments(self):
        '''
            These are kinda crappy/biased tests, but I know I iterate through
            the pcap packets and return all found.

            The more important tests, to me, are the ones where I handle edge cases.
        '''
        retval = pcap_util.split_packets_based_on_presence_of_field(tests.pcap,
                                                                    'http',
                                                                    'http.request.uri')

        assert retval is not None
        with_field = retval[0]
        without_field = retval[1]
        assert len(with_field) is len(with_field) is 30
        # assert len(retval) is 1
