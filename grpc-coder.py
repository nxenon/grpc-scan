"""
Encode and Decode GRPC-Web Base64 Encoded Payload for Pentesting GRPC-Web
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
    # convert for example 0a0d02 to \\x0a\\x0d\\x02

    temp_str = ""
    for i in range(0, len(hex_payload)):

        if i % 2 == 0:
            temp_str += r"\\x" + hex_payload[i]
        else:
            temp_str += hex_payload[i]

    return temp_str


def convert_hex_to_ascii(hex_input):
    hex_pairs = [hex_input[i:i + 2] for i in range(0, len(hex_input), 2)]

    ascii_string = [chr(int(pair, 16)) for pair in hex_pairs]
    ascii_string = [pair.encode('latin-1', errors='surrogateescape') for pair in ascii_string]
    ascii_string = ''.join(pair.decode('utf-8', errors='surrogateescape') for pair in ascii_string)

    return ascii_string


def convert_ascii_to_b64(ascii_input):
    encoded_b64 = base64.b64encode(ascii_input.encode('utf-8', 'surrogateescape'))
    return encoded_b64.decode('utf-8')


def get_padded_length_of_new_payload(payload):
    length = len(payload) / 2
    length = int(length)
    tmp = format(length, 'x')

    if len(tmp) < 10:
        tmp = "0" * (10 - len(tmp)) + tmp

    return tmp


def decoder(content_input):
    base64_decoded = decode_b64_payload(content_input)
    b64_to_hex = convert_to_hex(base64_decoded)
    payload_length_prefix, payload = split_grpc_length_prefix(b64_to_hex)
    length = calculate_length_from_length_prefix(payload_length_prefix)
    main_payload = read_payload_based_on_length(payload, length)
    # formatted_output = convert_payload_hex_to_formatted_output(main_payload)
    ascii_payload = convert_hex_to_ascii(main_payload)

    print(ascii_payload, end="")


def encoder(content_input):
    hex_converted = convert_to_hex(content_input.encode('utf-8', errors='surrogateescape'))
    hex_length_prefix = get_padded_length_of_new_payload(hex_converted)
    new_payload_with_length_prefix = hex_length_prefix + str(hex_converted.decode())
    ascii_result = convert_hex_to_ascii(new_payload_with_length_prefix)
    b64_result = convert_ascii_to_b64(ascii_result)
    print(b64_result)


def print_parser_help(prog):
    help_msg = f"""echo payload | python3 {prog} [--encode OR --decode]

    General Arguments:
      --encode      to encode protoscope tool binary output to grpc-web base64 encoded payload
      --decode      to decode grpc-web base64 encoded payload to protoscope tool hex format
    Help:
      --help        print help message
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
