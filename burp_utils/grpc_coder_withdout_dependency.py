"""
This is created to remove the protoscope binary dependency for burp suite
"""

import grpc_coder
import base64
import json
from collections import OrderedDict
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
sys.path.insert(0, "libs/blackboxprotobuf")
sys.path.insert(0, "libs/six")
import blackboxprotobuf


def decode_b64_grpc_web_text(payload):
    try:
        base64_decoded = grpc_coder.decode_b64_payload(payload)
        b64_to_hex = grpc_coder.convert_to_hex(base64_decoded)
        payload_length_prefix, payload = grpc_coder.split_grpc_length_prefix(b64_to_hex)
        length = grpc_coder.calculate_length_from_length_prefix(payload_length_prefix)
        main_payload = grpc_coder.read_payload_based_on_length(payload, length)
        ascii_payload = grpc_coder.new_method_convert_hex_to_ascii(main_payload)
        message, typedef = blackboxprotobuf.protobuf_to_json(ascii_payload)
        return message, typedef
    except Exception as e:
        raise e


def decode_grpc_web_proto_payload(payload):
    b64_payload = base64.b64encode(payload)
    b64_payload = b64_payload.decode('utf-8')
    msg, typedef = decode_b64_grpc_web_text(b64_payload)
    return msg, typedef


def encode_grpc_web_json_to_b64_format(json_payload, typedef):
    raw_paylaod = blackboxprotobuf.protobuf_from_json(json_payload, typedef)
    hex_converted = grpc_coder.convert_to_hex(raw_paylaod)
    hex_length_prefix = grpc_coder.get_padded_length_of_new_payload(hex_converted)
    new_payload_with_length_prefix = hex_length_prefix + str(hex_converted.decode())
    ascii_result = grpc_coder.new_method_convert_hex_to_ascii(new_payload_with_length_prefix)
    b64_result = grpc_coder.convert_ascii_to_b64(ascii_result)
    return b64_result


def encode_grpc_web_proto_json_to_proto_format(json_payload, typedef):
    raw_paylaod = blackboxprotobuf.protobuf_from_json(json_payload, typedef)
    hex_converted = grpc_coder.convert_to_hex(raw_paylaod)
    hex_length_prefix = grpc_coder.get_padded_length_of_new_payload(hex_converted)
    new_payload_with_length_prefix = hex_length_prefix + str(hex_converted.decode())
    ascii_result = grpc_coder.new_method_convert_hex_to_ascii(new_payload_with_length_prefix)
    return ascii_result


def get_main_json_from_type_def_ordered_dict(type_def):
    temp_dict = {}
    for k in type_def.keys():
        temp_dict[k] = type_def[k]['type']

    pretty_json = json.dumps(temp_dict, indent=1)
    return pretty_json


def create_bbpb_type_def_from_json(json_type_def):
    parsed_json = json.loads(json_type_def)
    temp_type_def = {}
    for k in parsed_json.keys():
        temp_type_def[str(k)] = OrderedDict([
            ('name', u''),
            ('type', parsed_json[k].decode('utf-8')),
            ('example_value_ignored', u'')
        ])

    return temp_type_def
