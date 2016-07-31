from pyshark_parser import pcap_util
from pyshark_parser import layer_util
import tests

layer = pcap_util.aggregate_layer(tests.pcap, 'tcp')[0]


class TestLayerHasFieldWithMatchingValue:

    def test_with_none_for_layer(self):
        retval = layer_util.layer_has_field_with_matching_value(None, '35324')

        assert not retval

    def test_with_none_for_value(self):
        retval = layer_util.layer_has_field_with_matching_value(layer, None)

        assert not retval

    def test_with_valid_arguments(self):
        port = layer.__dict__['_all_fields']['tcp.port']
        retval = layer_util.layer_has_field_with_matching_value(layer, port)

        assert retval

        port = str(int(port) + 1)

        retval = layer_util.layer_has_field_with_matching_value(layer, port)

        assert not retval
