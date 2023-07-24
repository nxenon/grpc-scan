"""
Encode and Decode GRPC-Web Base64 Encoded Payload for Pentesting GRPC-Web Easily
"""
import base64
import binascii
import sys
from argparse import ArgumentParser


def decode_b64_payload(b64_content):
    try:
        decoded = base64.b64decode(b64_content)
    except Exception as e:
        print('Error occurred while decoding b64 payload: ' + str(e))
        exit(1)

    return decoded


def convert_to_hex(content):
    try:
        hex_rep = binascii.hexlify(content)
    except Exception as e:
        print('Error occurred while converting payload to hex: ' + str(e))
        exit(1)

    return hex_rep


def split_grpc_length_prefix(hex_input):
    """
    split length prefix and payload from hex input
    :param hex_input:
    :return: length_prefix, payload
    """
    hex_input = hex_input.decode()
    length_prefix = hex_input[0:10]
    payload = hex_input[10:]

    return length_prefix, payload


def calculate_length_from_length_prefix(length_prefix):
    try:
        tmp = int(length_prefix, 16) * 2  # * 2 is bcs each byte has 2 characters
    except Exception as e:
        print('Error occurred while calculating length of payload: ' + str(e))
        exit(1)

    return tmp


def read_payload_based_on_length(payload, length):
    temp_str = payload[0:length]
    return temp_str


def convert_payload_hex_to_formatted_output(hex_payload):
    # convert for example 0a0d02 to \x0a\x0d\x02

    temp_str = ""
    for i in range(0, len(hex_payload)):

        if i % 2 == 0:
            temp_str += r"\x" + hex_payload[i]
        else:
            temp_str += hex_payload[i]

    return temp_str


def decoder(content_input):
    base64_decoded = decode_b64_payload(content_input)
    b64_to_hex = convert_to_hex(base64_decoded)
    payload_length_prefix, payload = split_grpc_length_prefix(b64_to_hex)
    length = calculate_length_from_length_prefix(payload_length_prefix)
    main_payload = read_payload_based_on_length(payload, length)
    result = convert_payload_hex_to_formatted_output(main_payload)
    print(result)


def encoder(content_input):
    print("TODO...")
    exit()


def print_parser_help(prog):
    help_msg = f"""echo payload | python3 {prog} [--encode OR --decode]

    General Arguments:
    --encode      to encode protoscope tool binary output to grpc-web base64 encoded payload
    --decode      to decode grpc-web base64 encoded payload to protoscope tool hex format
    Help:
      --help      print help message
"""

    print(help_msg)


def get_content_from_stdin():
    return sys.stdin.read()


if __name__ == '__main__':
    parser = ArgumentParser(usage='echo payload | python3 %(prog)s [--encode or --decode]',
                            allow_abbrev=False, add_help=False)

    parser.add_argument('--help', action='store_true', default=False)
    parser.add_argument('--encode', action='store_true')
    parser.add_argument('--decode', action='store_true')

    args, unknown = parser.parse_known_args()

    if (args.encode is not True) and (args.decode is not True):
        print_parser_help(parser.prog)
        exit(1)

    content = get_content_from_stdin()
    if args.decode is True:
        decoder(content)
    else:
        encoder(content)
