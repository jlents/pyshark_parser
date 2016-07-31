from __future__ import print_function
import pyshark
from pyshark_parser import packet_util
from pyshark_parser import layer_util


def get_layer_names(pcap):
    '''
        Returns list of the available layer names

        Args:
            pcap: the pyshark pcap object or list of packets

        Returns:
            list of string names for the different pcap layers
    '''
    if pcap is None:
        return None
    layer_names = set()
    for packet in pcap:
        for layer in packet.layers:
            layer_names.add(layer.__dict__['_layer_name'])
    return list(layer_names)


def get_all_values_for_layer_field(pcap, layer, field):
    '''
        Returns all values for the field in the specified layer

        Args:
            pcap: the pyshark pcap object or list of packets
            layer: name of the layer
            field: name of the field
        Returns:
            all values for the field in the specified layer
            or None, if any of the arguments are None
    '''
    if pcap is None or not layer or not field:
        return None
    values = set()
    for packet in pcap:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name'] and \
               field in current_layer.__dict__['_all_fields']:
                values.add(current_layer.__dict__['_all_fields'][field])
                break
    return values


def get_first_packet_with_layer_field_value(pcap, layer, field, value):
    '''
        Returns the first packet with matching field/value for layer

        Args:
            layer: name of the layer
            field: name of the field
            value: you guessed it.
        Returns:
            first packet with matching field/value in that layer
            or None, if any of the arguments are None
    '''
    if pcap is None or not layer or not field or not value:
        return None

    for packet in pcap:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name'] and \
               field in current_layer.__dict__['_all_fields'] and \
               value == current_layer.__dict__['_all_fields'][field]:
                return packet


def get_all_packets_with_layer_field_value(pcap, layer, field, value):
    '''
        Returns the all packets with matching value for field in layer

        Args:
            layer: name of the layer
            field: name of the field
            value: you guessed it.
        Returns:
            all packets with matching field/value in that layer
            or None, if any of the arguments are None
    '''
    if pcap is None or not layer or not field or not value:
        return None

    packets = []
    for packet in pcap:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name'] and \
               field in current_layer.__dict__['_all_fields'] and \
               value == current_layer.__dict__['_all_fields'][field]:
                packets.append(packet)
                break
    return packets


def get_all_packets_with_exact_value(pcap, value):
    '''
        Returns the all packets matching the specified value, in any layer.

        Args:
            pcap: the pyshark pcap object or list of packets
            value: the value being searched for
        Returns:
            all packets that have an exact match, ==, with the value
            or None, if any of the arguments are None
    '''
    if pcap is None or not value:
        return None

    packets = []
    for packet in pcap:
        for current_layer in packet.layers:
            if layer_util.layer_has_field_with_matching_value(current_layer, value):
                packets.append(packet)
                break

    return packets


def get_all_packets_with_value_contained(pcap, value):
    '''
        Returns the all packets containing the specified value anywhere.

        Args:
            pcap: the pyshark pcap object or list of packets
            value: the value being searched for
        Returns:
            all packets that has any value which contains the specified value
            or None, if any of the arguments are None
    '''
    if pcap is None or not value:
        return None

    packets = []
    for packet in pcap:
        for current_layer in packet.layers:
            if layer_util.layer_has_field_containing_value(current_layer, value):
                packets.append(packet)
                break

    return packets


def split_packets_based_on_presence_of_field(pcap, layer, field):
    '''
        Iterates over each packet in pcap and splits them based on the
        presence of the specified field.

        Args:
            pcap: the pyshark pcap object or list of packets
            layer: the string name of the layer that contains the field
            field: the string name of the field who's presence will be determined

        Returns:
            A tuple containing 2 lists of packets:
                1) the list of packets that contain the field
                2) the list of packets that do not contain the field

            or None, if any of the arguments are None
    '''
    if pcap is None or not layer or not field:
        return None

    with_field = []
    without_field = []
    for packet in pcap:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name']:
                if field in current_layer.__dict__['_all_fields']:
                    with_field.append(packet)
                else:
                    without_field.append(packet)
                break
    return with_field, without_field


def split_packets_based_on_match_of_value_in_field(pcap, layer, field, value):
    '''
        Iterates over each packet in pcap and splits them based on the
        specified value for the specified field.

        Args:
            pcap: the pyshark pcap or list of packets
            layer: the string name of the layer that contains the field
            field: the string name of the field who's value will be checked
            value: the value that will be compared

        Returns:
            A tuple containing 3 lists of packets:
                1) the list of packets that match the value
                2) the list of packets that do not match the value
                3) the list of packets that do not have the field

            or None, if any of the arguments are None

    '''
    if pcap is None or not layer or not field or not value:
        return None

    (with_field,
     without_field) = split_packets_based_on_presence_of_field(pcap,
                                                               layer,
                                                               field)
    with_value = []
    without_value = []
    for packet in with_field:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name']:
                if value == current_layer.__dict__['_all_fields'][field]:
                    with_value.append(packet)
                else:
                    without_value.append(packet)
                break

    return with_value, without_value, without_field


def aggregate_field_values_for_layer(pcap, layer, unique=False):
    '''
        Aggregates all values for each field in the specified layer.

        Args:
            pcap: the pyshark pcap or list of packets
            layer: the string name of the layer that the fields will be aggregated from
            unique: a boolean flag that indicates if you want a set or list back
        Returns:
            a dictionary with field names for keys and a list/set of values
            that were aggregated from the packets in pcap

            or None, if any of the arguments are None
    '''
    if pcap is None or not layer:
        return None

    fields = {}
    for packet in pcap:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name']:
                all_fields = current_layer.__dict__['_all_fields']
                for field in all_fields:
                    if field not in fields:
                        fields[field] = []
                    fields[field].append(all_fields[field])
                break

    if unique:
        new_fields = {}
        for field in fields:
            new_fields[field] = set(fields[field])
        fields = new_fields

    return fields


def aggregate_layer(pcap, layer):
    '''
        Gathers each layer from each packet in the pcap

        Args:
            pcap: the pyshark pcap object that the layers will be gathered from
            layer: the string name of the layer that will be aggregated

        Returns:
            list of the specified layer from each packet in pcap
            or None, if any of the arguments are None
    '''
    if pcap is None or not layer:
        return None

    layers = []
    for packet in pcap:
        for current_layer in packet.layers:
            if layer == current_layer.__dict__['_layer_name']:
                layers.append(current_layer)
                break
    return layers


def get_all_field_names(pcap, layer=None):
    '''
        Builds a unique list of field names that exist across all packets
        in the pcap for the specified layer.

        If no layer is provided, all layers are considered.

        Args:
            pcap: the pyshark pcap object the fields will be gathered from
            layer: the string name of the layer that will be targeted

        Returns:
            a set containing all unique field names
            or None, if pcap is None
    '''

    if pcap is None:
        return None

    field_names = set()
    for packet in pcap:
        for current_layer in packet.layers:
            if not layer or layer == current_layer.__dict__['_layer_name']:
                for field in current_layer.__dict__['_all_fields']:
                    field_names.add(field)
    return field_names
