from pyshark_parser import pcap_util
from pyshark_parser import layer_util
import tests

layer = pcap_util.aggregate_layer(tests.pcap, 'http')[0]
part_of_uri = 'MzUK.php'


class TestLayerHasFieldContainingValue:

    def test_with_none_for_layer(self):
        retval = layer_util.layer_has_field_containing_value(None, part_of_uri)

        assert not retval

    def test_with_none_for_value(self):
        retval = layer_util.layer_has_field_containing_value(layer, None)

        assert not retval

    def test_with_valid_arguments(self):
        retval = layer_util.layer_has_field_containing_value(layer, part_of_uri)

        assert retval

        altered = '1' + part_of_uri
        retval = layer_util.layer_has_field_with_matching_value(layer, altered)

        assert not retval
