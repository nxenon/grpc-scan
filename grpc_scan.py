"""
GRPC-Scan
Extracting Methods, Services and Messages (Routes) in JS files (grpc-web)
"""

import re
from argparse import ArgumentParser
import sys
import jsbeautifier
from texttable import Texttable


def create_table(columns_list, rows_list):
    table = Texttable()

    table_list = [columns_list]
    for i in rows_list:
        table_list.append(i)
    table.add_rows(table_list)
    table_string = table.draw()
    # indented_table_string = '    ' + table_string.replace('\n', '\n    ')  # Add space before each line

    return table_string


def beautify_js_content(content):
    try:
        beautified = jsbeautifier.beautify(content)

    except Exception as e:
        print('An error occurred in beautifying Javascript code: ' + str(e))
        print('Enter valid javascript code. Do not copy js code '
              'from browser dev tools directly! try to download it directly!')
        print('If you are still getting this error, try to beautify Javascript code online and then use this tool!')
        exit(1)

    return beautified


def extract_endpoints(content):
    pattern = r'MethodDescriptor\("(\/.*?)"'
    compiled_pattern = re.compile(pattern)
    matched_items = compiled_pattern.findall(content)
    matched_items = list(matched_items)
    print('Found Endpoints:')
    if matched_items:
        for m in matched_items:
            print("  " + m)

    print()


def extract_messages(content):
    pattern = r'proto\.(.*)\.prototype\.set(.*).*=.*function\(.*\).*{\s*.*set(.*)\(.*?,(.*?),'
    compiled_pattern = re.compile(pattern)
    matched_items = compiled_pattern.findall(content)
    matched_items = list(matched_items)

    message_list = {}

    print('Found Messages:')
    if matched_items:
        for m in matched_items:

            if m[0].strip() not in message_list:
                message_list[m[0]] = []
            if m[1].strip() not in message_list[m[0].strip()]:
                # add proto field *name* 1, add proto field *type* 2, add proto field *number* 3
                temp_list = [m[1].strip(), m[2].strip(), m[3].strip()]
                message_list[m[0]].append(temp_list)

        for m2 in message_list.keys():
            print()
            print(f'{m2}:')
            print(create_table(columns_list=['Field Name', 'Field Type', 'Field Number'], rows_list=message_list[m2]))

    print()


def read_file(file):
    try:
        with open(file, 'r', encoding='utf-8') as file:
            return file.read()

    except Exception as e:
        print('Error occurred on opening file: ' + str(e))
        exit(1)


def read_standard_input():
    return sys.stdin.read()


def print_parser_help(prog):
    help_msg = f"""python3 {prog} [INPUT]
    
    Input Arguments:
      --file      file name of js file
      --stdin     get input from standard input
    Help:
      --help      print help message
"""

    print(help_msg)


if __name__ == "__main__":
    parser = ArgumentParser(usage='python3 %(prog)s [INPUT]',
                            allow_abbrev=False, add_help=False)

    parser.add_argument('--help', action='store_true', default=False)
    parser.add_argument('--file')
    parser.add_argument('--stdin', action='store_true', default=False)

    args, unknown = parser.parse_known_args()

    if (args.help is True) or (args.file is None):
        if args.stdin is not True:
            print_parser_help(prog=parser.prog)
            exit(0)

    js_content = ""

    if args.file is not None:
        js_content = read_file(args.file)
    else:
        js_content = read_standard_input()

    js_content = beautify_js_content(js_content)

    extract_endpoints(js_content)
    extract_messages(js_content)
