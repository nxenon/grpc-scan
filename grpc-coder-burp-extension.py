from burp import IBurpExtender
from burp import IContextMenuFactory, IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JMenuItem
import subprocess
from java.lang import System
import os
import commands


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName('gRPC-Web Coder')
        callbacks.registerContextMenuFactory(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

    def createMenuItems(self, invocation):

        context = invocation.getInvocationContext()

        selected_payload = self.get_selected_text(invocation)
        payload_index = self.get_index_of_selected_text(invocation)
        if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
                or context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
                and selected_payload is not None:

            label_encode = 'Encode'
            label_decode = 'Decode'
            menu_item_encoding = JMenuItem(label_encode, actionPerformed=self.encode_payload)
            menu_item_encoding.putClientProperty('grpc_selected_payload', selected_payload)
            menu_item_encoding.putClientProperty('grpc_selected_payload_index', payload_index)
            menu_item_encoding.putClientProperty('grpc_encoding_invocation', invocation)

            menu_item_decoding = JMenuItem(label_decode, actionPerformed=self.decode_payload)
            menu_item_decoding.putClientProperty('grpc_selected_payload', selected_payload)
            menu_item_decoding.putClientProperty('grpc_selected_payload_index', payload_index)
            menu_item_decoding.putClientProperty('grpc_decoding_invocation', invocation)

            return [menu_item_encoding, menu_item_decoding]

    def get_selected_text(self, invocation):
        request_text = invocation.getSelectedMessages()[0].getRequest().tostring()

        text_index = invocation.getSelectionBounds()
        start_index = text_index[0]
        end_index = text_index[1]

        selected_text = request_text[start_index:end_index]

        return selected_text

    def get_index_of_selected_text(self, invocation):
        request_text = invocation.getSelectedMessages()[0].getRequest().tostring()

        text_index = invocation.getSelectionBounds()
        start_index = text_index[0]
        end_index = text_index[1]

        return (start_index, end_index)

    def update_request(self, invocation, index, new_payload):
        # index is a tuple --> (start_index, end_index)
        self.pprint(22)
        old_request_string = invocation.getSelectedMessages()[0].getRequest().tostring()
        self.pprint(old_request_string)
        new_request_string = old_request_string[:index[0]] + new_payload + old_request_string[index[1] + 1:]
        new_request_bytes = self.helpers.stringToBytes(new_request_string)
        invocation.getSelectedMessages()[0].setRequest(new_request_bytes)

    def encode_payload(self, event):

        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('grpc_selected_payload')
        _invocation = menu_item.getClientProperty('grpc_encoding_invocation')
        _index = menu_item.getClientProperty('grpc_selected_payload_index')

        temp_file_path = 'grpc_coder_output_encode.txt'

        with open(temp_file_path, "w") as file:
            file.write(selected_payload.strip())

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"
        else:
            status, _ = commands.getstatusoutput('which python')
            if status != 0:
                python_name = "python3"

        command = "protoscope -s grpc_coder_output_encode.txt | " + python_name + " grpc-coder.py --encode"
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e:
                pass

        if output:
            self.update_request(_invocation, _index, output)

        return None

    def decode_payload(self, event):
        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('grpc_selected_payload')
        _invocation = menu_item.getClientProperty('grpc_decoding_invocation')
        _index = menu_item.getClientProperty('grpc_selected_payload_index')

        temp_file_path = 'grpc_coder_output_decode.txt'

        with open(temp_file_path, "w") as file:
            file.write(selected_payload.strip())

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"
        else:
            status, _ = commands.getstatusoutput('which python')
            if status != 0:
                python_name = "python3"

        command = python_name + " grpc-coder.py --decode --file grpc_coder_output_decode.txt | protoscope"
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e:
                pass

        if output:
            self.update_request(_invocation, _index, output)

        return None

    def process_http_message(self):
        pass

    def pprint(self, text):
        self.stdout.println(text)
