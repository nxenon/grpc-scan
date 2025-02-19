# grpc_utils.py
import subprocess
import os

import traceback
# Add at the top of the file:
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

PROTOSCOPE_PATH = "protoscope"


def extract_value_from_path(field_path, message):
    """Extract the value at the specified field path"""
    if not field_path:
        return message

    lines = message.split('\n')
    path_stack = []

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        while path_stack and indent <= path_stack[-1][0]:
            path_stack.pop()

        if ': {' in stripped:
            field_num = stripped.split(':', 1)[0].strip()
            value = stripped.split('{', 1)[1].rstrip('}').strip()

            path_stack.append((indent, field_num))
            current_path = [p[1] for p in path_stack]

            if current_path == field_path:
                if value.startswith('"') and value.endswith('"'):
                    return value[1:-1]
                return value

    return None


def replace_value_at_path(message, field_path, new_value):
    """Replace value at the specified field path (escaping included)"""

    def escape_value(val):
        val = str(val)
        val = val.replace('\\', '\\\\').replace('"', '\\"')
        val = val.replace('\n', '\\n').replace('\r', '\\r')
        return '"{}"'.format(val)

    if not field_path:
        return message

    lines = message.split('\n')
    result = []
    path_stack = []

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        while path_stack and indent <= path_stack[-1][0]:
            path_stack.pop()

        if ': {' in stripped:
            field_num = stripped.split(':', 1)[0].strip()
            path_stack.append((indent, field_num))

            current_path = [p[1] for p in path_stack]
            if current_path == field_path:
                escaped = escape_value(new_value)
                new_line = ' ' * indent + field_num + ': {' + escaped + '}'
                result.append(new_line)
                continue

        result.append(line)

    return '\n'.join(result)


def find_insertion_points(decoded_message):
    """Find all possible insertion points in a decoded protobuf message"""
    insertion_points = []

    def parse_message(message, current_path=[]):
        """Recursively parse protobuf message to find all fields"""
        lines = message.split('\n')
        path_stack = []
        current_indent = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            indent = len(line) - len(stripped)

            # Adjust path stack based on indentation
            while path_stack and indent <= path_stack[-1][0]:
                path_stack.pop()

            if ': {' in stripped:
                field_num = stripped.split(':', 1)[0].strip()
                value = stripped.split('{', 1)[1].rstrip('}').strip()

                path_stack.append((indent, field_num))
                new_path = [p[1] for p in path_stack]

                if value == '':
                    continue
                # Add the current field as an insertion point
                insertion_points.append({
                    'path': new_path,
                    'name': "gRPC field {}".format('.'.join(new_path)),
                    'value': value
                })

                # If the value contains nested structure, parse it
                if value.count('{') > value.count('"'):
                    parse_message(value, new_path)

    parse_message(decoded_message)
    return insertion_points


def get_decoded_payload_grpc_web_text(payload):
    temp_file_path = 'grpc_coder_output_decode.txt'
    temp_proto_path = 'proto_output.txt'

    try:
        # If payload is bytes, keep it as-is for base64
        if isinstance(payload, bytes):
            raw_payload = payload
        else:
            # If string/unicode, encode to ascii, ignoring problematic chars
            raw_payload = payload.encode('ascii', 'ignore')

        # Write raw bytes
        with open(temp_file_path, 'wb') as file:
            file.write(raw_payload)

        python_name = "python"
        if not os.name.startswith("Windows"):
            try:
                status = subprocess.check_output('which python3', shell=True)
                python_name = "python3"
            except subprocess.CalledProcessError:
                python_name = "python"

        command = [python_name, "grpc_coder.py", "--decode", "--file", temp_file_path]
        decoded = subprocess.check_output(command, shell=False)

        with open(temp_proto_path, 'wb') as f:
            f.write(decoded)

        try:
            protoscope_command = [PROTOSCOPE_PATH, temp_proto_path]
            protoscope_output = subprocess.check_output(protoscope_command, shell=False)
            return protoscope_output
        except subprocess.CalledProcessError as e:
            return decoded

    except:
        return payload
    finally:
        for temp_file in [temp_file_path, temp_proto_path]:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass


def get_encoded_payload_grpc_web_text(payload):
    temp_file_path_encoding = 'grpc_coder_output_encode.txt'
    temp_proto_path = 'proto_output.txt'

    try:
        # If payload is bytes, keep it as-is for base64
        if isinstance(payload, bytes):
            raw_payload = payload
        else:
            # If string/unicode, encode to ascii, ignoring problematic chars
            raw_payload = payload.encode('ascii', 'ignore')

        # Write raw bytes
        with open(temp_file_path_encoding, 'wb') as file:
            file.write(raw_payload)

        python_name = "python"
        if not os.name.startswith("Windows"):
            try:
                status = subprocess.check_output('which python3', shell=True)
                python_name = "python3"
            except subprocess.CalledProcessError:
                python_name = "python"

        try:
            protoscope_command = [PROTOSCOPE_PATH, "-s", temp_file_path_encoding]
            with open(temp_proto_path, 'wb') as f:
                subprocess.check_call(protoscope_command, stdout=f, shell=False)

            encode_command = [python_name, "grpc_coder.py", "--encode", "--file", temp_proto_path]
            output = subprocess.check_output(encode_command, shell=False)
            return output.strip()

        except subprocess.CalledProcessError:
            encode_command = [python_name, "grpc_coder.py", "--encode", "--file", temp_file_path_encoding]
            output = subprocess.check_output(encode_command, shell=False)
            return output.strip()

    except:
        return payload
    finally:
        for temp_file in [temp_file_path_encoding, temp_proto_path]:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass