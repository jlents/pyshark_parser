from pyshark_parser import pcap_util
import tests

all_fields = {'', '_ws.expert', '_ws.expert.group', '_ws.expert.message',
              '_ws.expert.severity', 'data', 'data.data', 'data.len', 'http.accept',
              'http.accept_encoding', 'http.accept_language', 'http.chat',
              'http.connection', 'http.host', 'http.referer', 'http.request',
              'http.request.full_uri', 'http.request.line', 'http.request.method',
              'http.request.uri', 'http.request.version', 'http.request_number',
              'http.user_agent', 'ip.addr', 'ip.checksum', 'ip.checksum_bad',
              'ip.checksum_good', 'ip.dsfield', 'ip.dsfield.dscp', 'ip.dsfield.ecn',
              'ip.dst', 'ip.dst_host', 'ip.flags', 'ip.flags.df', 'ip.flags.mf',
              'ip.flags.rb', 'ip.frag_offset', 'ip.hdr_len', 'ip.host', 'ip.id',
              'ip.len', 'ip.proto', 'ip.src', 'ip.src_host', 'ip.ttl', 'ip.version',
              'sll.etype', 'sll.halen', 'sll.hatype', 'sll.pkttype', 'sll.src.eth',
              'tcp.ack', 'tcp.analysis', 'tcp.analysis.ack_rtt', 'tcp.analysis.acks_frame',
              'tcp.analysis.bytes_in_flight', 'tcp.checksum', 'tcp.checksum_bad',
              'tcp.checksum_good', 'tcp.dstport', 'tcp.flags', 'tcp.flags.ack',
              'tcp.flags.cwr', 'tcp.flags.ecn', 'tcp.flags.fin', 'tcp.flags.ns',
              'tcp.flags.push', 'tcp.flags.res', 'tcp.flags.reset', 'tcp.flags.str',
              'tcp.flags.syn', 'tcp.flags.urg', 'tcp.hdr_len', 'tcp.len', 'tcp.nxtseq',
              'tcp.option_kind', 'tcp.option_len', 'tcp.options',
              'tcp.options.timestamp.tsecr', 'tcp.options.timestamp.tsval',
              'tcp.options.type', 'tcp.options.type.class', 'tcp.options.type.copy',
              'tcp.options.type.number', 'tcp.port', 'tcp.seq', 'tcp.srcport',
              'tcp.stream', 'tcp.urgent_pointer', 'tcp.window_size',
              'tcp.window_size_scalefactor', 'tcp.window_size_value'}

tcp_fields = {'', 'tcp.ack', 'tcp.analysis', 'tcp.analysis.ack_rtt',
              'tcp.analysis.acks_frame', 'tcp.analysis.bytes_in_flight',
              'tcp.checksum', 'tcp.checksum_bad', 'tcp.checksum_good',
              'tcp.dstport', 'tcp.flags', 'tcp.flags.ack', 'tcp.flags.cwr',
              'tcp.flags.ecn', 'tcp.flags.fin', 'tcp.flags.ns', 'tcp.flags.push',
              'tcp.flags.res', 'tcp.flags.reset', 'tcp.flags.str', 'tcp.flags.syn',
              'tcp.flags.urg', 'tcp.hdr_len', 'tcp.len', 'tcp.nxtseq',
              'tcp.option_kind', 'tcp.option_len', 'tcp.options',
              'tcp.options.timestamp.tsecr', 'tcp.options.timestamp.tsval',
              'tcp.options.type', 'tcp.options.type.class', 'tcp.options.type.copy',
              'tcp.options.type.number', 'tcp.port', 'tcp.seq', 'tcp.srcport',
              'tcp.stream', 'tcp.urgent_pointer', 'tcp.window_size',
              'tcp.window_size_scalefactor', 'tcp.window_size_value'}


class TestGetAllFieldNames:

    def test_with_none_for_packet(self):
        retval = pcap_util.get_all_field_names(None)
        assert retval is None

    def test_with_single_layer(self):
        retval = pcap_util.get_all_field_names(tests.pcap, 'tcp')
        assert retval == tcp_fields

    def test_with_none_for_layer(self):
        retval = pcap_util.get_all_field_names(tests.pcap)
        assert retval == all_fields
