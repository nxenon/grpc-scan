"""
This is created to remove the protoscope binary dependency for burp suite
"""
import sys

import grpc_coder
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


def encode_grpc_web_json_to_b64_format(json_payload, typedef):
    pass
