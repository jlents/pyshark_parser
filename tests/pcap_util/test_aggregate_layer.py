from pyshark_parser import pcap_util
import tests
import pyshark


class TestAggregateLayer:
    def test_with_none_for_pcap(self):
        retval = pcap_util.aggregate_layer(None,
                                           'http')

        assert retval is None

    def test_with_none_for_layer(self):
        retval = pcap_util.aggregate_layer(tests.pcap,
                                           None)

        assert retval is None

    def test_with_valid_arguments(self):
        retval = pcap_util.aggregate_layer(tests.pcap,
                                           'http')

        assert retval is not None
        assert len(retval) is 60
        for current_layer in retval:
            assert isinstance(current_layer, pyshark.packet.layer.Layer)
            assert current_layer.__dict__['_layer_name'] == 'http'
