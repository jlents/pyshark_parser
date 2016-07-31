from pyshark_parser import pcap_util
import tests


class TestGetLayerNames:
    def test_with_none(self):
        retval = pcap_util.get_layer_names(None)
        assert retval is None

    def test_with_valid_input(self):
        expected = ['sll', 'ip', 'http', 'tcp']
        retval = pcap_util.get_layer_names(tests.pcap)
        assert len(expected) == len(retval)
        assert expected == retval
