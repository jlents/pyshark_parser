def discover_all_fields_that_match_value(packet, value):
    '''
        Builds a dictionary, with each layer name as a key, containing a list
        of each field, in that layer, that matches the value exactly

        Args:
            packet: a single packet, that will be inspected
            value: the value that all fields in the packet will be inspected for.

        Returns:
            a dictionary of lists
            or None, if any of the arguments are None
            example:
                {'http': ['http.request.uri']}
    '''
    if not packet or not value:
        return None

    matches = {}
    for current_layer in packet.layers:
        fields = current_layer.__dict__['_all_fields']
        layer_name = current_layer.__dict__['_layer_name']
        for field in fields:
            if value == fields[field]:
                if layer_name not in matches:
                    matches[layer_name] = []
                matches[layer_name].append(field)
    return matches


def discover_all_fields_that_contain_value(packet, value):
    '''
        Builds a dictionary, with each layer name as a key, containing a list
        of each field, in that layer, that contains the value

        It doesn't have to be an exact match, it only has to contain the value.
        i.e. '20' is contained in '13203'

        Args:
            packet: a single packet, that will be inspected
            value: the value that all fields in the packet will be inspected for.

        Returns:
            a dictionary of lists
            or None, if any of the arguments are None
            example:
                {'http': ['http.request.uri']}
    '''
    if not packet or not value:
        return None

    matches = {}
    for current_layer in packet.layers:
        fields = current_layer.__dict__['_all_fields']
        layer_name = current_layer.__dict__['_layer_name']
        for field in fields:
            if value in fields[field]:
                if layer_name not in matches:
                    matches[layer_name] = []
                matches[layer_name].append(field)
    return matches


def get_value_from_packet_for_layer_field(packet, layer, field):
    '''
        Gets the value from the packet for the specified 'layer' and 'field'

        Args:
            packet: The packet where you'll be retrieving the value from
            layer: The layer that contains the field
            field: The field that contains the value

        Returns:
            the value at packet[layer][key] or None
            or None, if any of the arguments are None
    '''
    if not packet or not layer or not field:
        return None
    for current_layer in packet.layers:
        if layer == current_layer.__dict__['_layer_name'] and \
           current_layer.__dict__['_all_fields']:
            return current_layer.__dict__['_all_fields'][field]
    return None


def get_all_field_names(packet, layer=None):
    '''
        Builds a unique list of field names, that exist in the packet,
        for the specified layer.

        If no layer is provided, all layers are considered.

        Args:
            packet: the pyshark packet object the fields will be gathered from
            layer: the string name of the layer that will be targeted

        Returns:
            a set containing all unique field names
            or None, if packet is None
    '''

    if not packet:
        return None

    field_names = set()
    for current_layer in packet.layers:
        if not layer or layer == current_layer.__dict__['_layer_name']:
            for field in current_layer.__dict__['_all_fields']:
                field_names.add(field)
    return field_names
