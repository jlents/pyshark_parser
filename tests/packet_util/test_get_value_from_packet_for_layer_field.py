from pyshark_parser import pcap_util
from pyshark_parser import packet_util
import tests

packet = tests.first_packet
value = packet.layers[3].__dict__['_all_fields']['http.request.uri']


class TestGetValueFromPacketForLayerField:
    def test_with_none_for_packet(self):
        retval = packet_util.get_value_from_packet_for_layer_field(None,
                                                                   'http',
                                                                   'http.request.uri')

        assert retval is None

    def test_with_none_for_layer(self):
        retval = packet_util.get_value_from_packet_for_layer_field(packet,
                                                                   None,
                                                                   'http.request.uri')

        assert retval is None

    def test_with_none_for_field(self):
        retval = packet_util.get_value_from_packet_for_layer_field(packet,
                                                                   'http',
                                                                   None)

        assert retval is None

    def test_with_valid_arguments(self):
        retval = packet_util.get_value_from_packet_for_layer_field(packet,
                                                                   'http',
                                                                   'http.request.uri')

        assert retval is not None
        assert retval == value
