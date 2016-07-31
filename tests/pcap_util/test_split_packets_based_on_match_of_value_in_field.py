from pyshark_parser import pcap_util
import tests


uri = '/MjcK.php?=owVXdTMzc1V3EzMXd1NxMjLucTMzszO3EzM7szNxMzO7cTMzszO3EzM7szNxMzO7cTMzszO3EzM7szNxMzO7cTMzszO3EzM7szNxMzO7cTMzszO3EzM7sz&L4bry1nth_17127?NxMzO7cTMzszO3EzMmtzNxMzO7cTMzsjL3EzMuszNxMzO7cTMzszO3EzM74yNxMjL7cTMz4yV3EzMXd1NxMzVXdTMzc1V3EzMX5yNxMjLXdTMzYlL3EzM74yNxMjLucTMzc1V3EzM-26754%26%71%77port%3D27500'


class TestSplitPacketsBaseOnMatchOfValueInField:
    def test_with_none_for_pcap(self):
        retval = pcap_util.split_packets_based_on_match_of_value_in_field(None,
                                                                          'http',
                                                                          'http.request.uri',
                                                                          uri)

        assert retval is None

    def test_with_none_for_value(self):
        retval = pcap_util.split_packets_based_on_match_of_value_in_field(tests.pcap,
                                                                          None,
                                                                          'http.request.uri',
                                                                          uri)

        assert retval is None

    def test_with_none_for_value(self):
        retval = pcap_util.split_packets_based_on_match_of_value_in_field(tests.pcap,
                                                                          'http',
                                                                          None,
                                                                          uri)

        assert retval is None

    def test_with_valid_arguments(self):
        '''
            These are kinda crappy/biased tests, but I know I iterate through
            the pcap packets and return all found.

            The more important tests, to me, are the ones where I handle edge cases.
        '''
        retval = pcap_util.split_packets_based_on_match_of_value_in_field(tests.pcap,
                                                                          'http',
                                                                          'http.request.uri',
                                                                          uri)

        assert retval is not None
        with_value = retval[0]
        without_value = retval[1]
        without_field = retval[2]
        assert len(with_value) is 1
        assert len(without_value) is 29
        assert len(without_field) is 30
