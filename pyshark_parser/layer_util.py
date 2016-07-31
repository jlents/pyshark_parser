def collect_unique_values_from_single_layer_array(layer_array):
    '''
        Iterates over each layer in the layer_array and aggregates all unique
        values into a map with sets as the values

        Args:
            layer_array: an array of layer obects (pyshark.packet.layer.Layer)

        Returns
            dictionary where the keys are the individual fields in the layer
            and the values are a set of all the unique values for that field
            across the array.

            or None, if layer_array is None


            i.e. {'tcp.window_size': {'4099', '6144'}}
    '''
    if not layer_array:
        return None

    the_diff = {}
    for packet_layer in layer_array:
        layer = packet_layer.__dict__['_all_fields']
        for field in layer:
            field_str = str(layer[field])
            # TODO: use defaultdict
            if field not in the_diff:
                the_diff[field] = set()
            if field_str not in the_diff[field]:
                the_diff[field].add(field_str)
    return the_diff


def layer_has_field_with_matching_value(layer, value):
    '''
        Determines if any field, in the layer, exactly matches the specified value.

        Args:
            layer: the pyshark layer object which will be searched for the value
            value: the value being searched for
        Returns:
            True: if value exactly matches the value in any of the fields for the layer
            False: otherwise
    '''
    if not layer or not value:
        return False

    fields = layer.__dict__['_all_fields']
    for field in layer.__dict__['_all_fields']:
        if value == fields[field]:
            return True
    return False


def layer_has_field_containing_value(layer, value):
    '''
        Determines if any field, in the layer, contains the specified value.
        It doesn't have to be an exact match, it only has to contain the value.
        i.e. '20' is contained in '13203'

        Args:
            layer: the pyshark layer object which will be searched for value
            value: the value being searched for
        Returns:
            True: if value is contained in the value from any of the fields for the layer
            False: otherwise
    '''
    if not layer or not value:
        return False

    fields = layer.__dict__['_all_fields']
    for field in layer.__dict__['_all_fields']:
        if value in fields[field]:
            return True
    return False
