from pyshark_parser import pcap_util
import tests

layer = 'http'
field = 'http.user_agent'
user_agents = set(['Mozilla/2.02Gold (Win95; I)'])
tcp_srcport = {'35301', '35302', '35303', '35304', '35305', '35306', '35307',
               '35308', '35309', '35310', '35311', '35312', '35313', '35314',
               '35315', '35316', '35317', '35318', '35319', '35320', '35321',
               '35322', '35323', '35324', '35325', '35326', '35327', '35328',
               '35329', '35330', '80'}


class TestGetAllValuesForLayerField:

    def test_with_none_for_pcap(self):
        retval = pcap_util.get_all_values_for_layer_field(None, layer, field)
        assert not retval

    def test_with_none_for_layer(self):
        retval = pcap_util.get_all_values_for_layer_field(tests.pcap, None, field)
        assert not retval

    def test_with_none_for_field(self):
        retval = pcap_util.get_all_values_for_layer_field(tests.pcap, layer, None)
        assert not retval

    def test_with_valid_parameters(self):
        retval = pcap_util.get_all_values_for_layer_field(tests.pcap, layer, field)
        assert retval == user_agents

        retval = pcap_util.get_all_values_for_layer_field(tests.pcap, 'tcp', 'tcp.srcport')
        assert retval == tcp_srcport
