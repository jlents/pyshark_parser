from pyshark_parser import pcap_util
import tests


uri = '/MjcK.php?=owVXdTMzc1V3EzMXd1NxMjLucTMzszO3EzM7szNxMzO7cTMzszO3EzM7szNxMzO7cTMzszO3EzM7szNxMzO7cTMzszO3EzM7szNxMzO7cTMzszO3EzM7sz&L4bry1nth_17127?NxMzO7cTMzszO3EzMmtzNxMzO7cTMzsjL3EzMuszNxMzO7cTMzszO3EzM74yNxMjL7cTMz4yV3EzMXd1NxMzVXdTMzc1V3EzMX5yNxMjLXdTMzYlL3EzM74yNxMjLucTMzc1V3EzM-26754%26%71%77port%3D27500'


class TestGetAllPacketsWithExactValue:
    def test_with_none_for_pcap(self):
        retval = pcap_util.get_all_packets_with_exact_value(None,
                                                            'tcp')

        assert retval is None

    def test_with_none_for_value(self):
        retval = pcap_util.get_all_packets_with_exact_value(tests.pcap,
                                                            None)

        assert retval is None

    def test_with_valid_arguments(self):
        '''
            These are kinda crappy/biased tests, but I know I iterate through
            the pcap packets and return all found.

            The more important tests, to me, are the ones where I handle edge cases.
        '''
        retval = pcap_util.get_all_packets_with_exact_value(tests.pcap,
                                                            uri)

        assert retval is not None
        assert len(retval) is 1
