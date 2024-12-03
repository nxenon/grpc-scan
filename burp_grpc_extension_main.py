from burp import IBurpExtender
from burp import IContextMenuFactory, IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JMenuItem
import subprocess
from java.lang import System
import os
import commands
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IIntruderPayloadProcessor
import traceback

import grpc_utils
from burp_grpc_decodetab import ProtoDecodeTab
from burp_grpc_insertionpoint import GrpcInsertionPoint


class BurpExtender(IBurpExtender, IContextMenuFactory, IMessageEditorTabFactory, IScannerInsertionPointProvider, IIntruderPayloadProcessor):

    def registerExtenderCallbacks(self, callbacks):
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName('gRPC-Web Coder')
        callbacks.registerContextMenuFactory(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerScannerInsertionPointProvider(self)
        callbacks.registerIntruderPayloadProcessor(self)
        self._callbacks = callbacks

    def getInsertionPoints(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        requestInfo = self.helpers.analyzeRequest(request)

        # check if gRPC request
        headers = requestInfo.getHeaders()
        isGrpc = False
        for header in headers:
            if header.lower().startswith("content-type: application/grpc-web-text"):
                isGrpc = True
                break

        if not isGrpc:
            return None

        body = request[requestInfo.getBodyOffset():]
        decoded = self.decode_grpc_payload(body)

        try:
            # Use the new find_insertion_points function
            found_points = grpc_utils.find_insertion_points(decoded)

            # Convert the found points into Burp insertion points
            insertionPoints = []
            for point in found_points:
                insertionPoints.append(
                    GrpcInsertionPoint(
                        self,
                        request,
                        requestInfo.getBodyOffset(),
                        decoded,
                        point['name'],  # Using the name from the found point
                        field_path=point['path']  # Using the path from the found point
                    )
                )

            return insertionPoints

        except:
            print("Error creating insertion points")
            print(traceback.format_exc())
            return None

    def getProcessorName(self):
        return "gRPC Payload Processor"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        """Implement IIntruderPayloadProcessor"""
        # Encode the payload for gRPC
        try:
            payload = self.helpers.bytesToString(currentPayload)
            encoded = grpc_utils.get_encoded_payload_grpc_web_text(payload)
            return self.helpers.stringToBytes(encoded)
        except:
            return currentPayload

    def decode_grpc_payload(self, payload):
        """decode gRPC payload"""
        try:
            payload_str = self.helpers.bytesToString(payload)
            return grpc_utils.get_decoded_payload_grpc_web_text(payload_str)
        except:
            print("Error decoding gRPC payload")
            print(traceback.format_exc())
            print(str(payload))
            return payload

    def createNewInstance(self, controller, editable):
        
        return ProtoDecodeTab(self, controller, editable, self.helpers)

    def createMenuItems(self, invocation):

        context = invocation.getInvocationContext()

        selected_payload = self.get_selected_text(invocation)
        payload_index = self.get_index_of_selected_text(invocation)
        if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
                or context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
                and selected_payload is not None:

            label_encode_grpc_web_text = 'Encode application/grpc-web-text'
            label_decode_grpc_web_text = 'Decode application/grpc-web-text'

            menu_item_encoding_grpc_web_text = JMenuItem(label_encode_grpc_web_text, actionPerformed=self.encode_payload_grpc_web_text)
            menu_item_encoding_grpc_web_text.putClientProperty('grpc_selected_payload', selected_payload)
            menu_item_encoding_grpc_web_text.putClientProperty('grpc_selected_payload_index', payload_index)
            menu_item_encoding_grpc_web_text.putClientProperty('grpc_encoding_invocation', invocation)

            menu_item_decoding_grpc_web_text = JMenuItem(label_decode_grpc_web_text, actionPerformed=self.decode_payload_grpc_web_text)
            menu_item_decoding_grpc_web_text.putClientProperty('grpc_selected_payload', selected_payload)
            menu_item_decoding_grpc_web_text.putClientProperty('grpc_selected_payload_index', payload_index)
            menu_item_decoding_grpc_web_text.putClientProperty('grpc_decoding_invocation', invocation)

            # label_encode_grpc_web = 'Encode application/grpc-web+proto'
            # label_decode_grpc_web = 'Decode application/grpc-web+proto'
            #
            # menu_item_encoding_grpc_web = JMenuItem(label_encode_grpc_web, actionPerformed=self.encode_payload_grpc_web)
            # menu_item_encoding_grpc_web.putClientProperty('grpc_selected_payload', selected_payload)
            # menu_item_encoding_grpc_web.putClientProperty('grpc_selected_payload_index', payload_index)
            # menu_item_encoding_grpc_web.putClientProperty('grpc_encoding_invocation', invocation)
            #
            # menu_item_decoding_grpc_web = JMenuItem(label_decode_grpc_web, actionPerformed=self.decode_payload_grpc_web)
            # menu_item_decoding_grpc_web.putClientProperty('grpc_selected_payload', selected_payload)
            # menu_item_decoding_grpc_web.putClientProperty('grpc_selected_payload_index', payload_index)
            # menu_item_decoding_grpc_web.putClientProperty('grpc_decoding_invocation', invocation)

            label_big_string_chunker = 'Chunk Big String'
            menu_item_big_string_chunker = JMenuItem(label_big_string_chunker, actionPerformed=self.chunk_big_string)
            menu_item_big_string_chunker.putClientProperty('big_string_selected_payload', selected_payload)
            menu_item_big_string_chunker.putClientProperty('big_string_selected_payload_index', payload_index)
            menu_item_big_string_chunker.putClientProperty('big_string_invocation', invocation)

            label_un_chunk_chunked_string = 'Un-Chunk Chunked String'
            menu_item_un_chunk_chunked_string = JMenuItem(
                label_un_chunk_chunked_string,
                actionPerformed=self.un_chunk_chunked_string
            )
            menu_item_un_chunk_chunked_string.putClientProperty('chunked_string_selected_payload', selected_payload)
            menu_item_un_chunk_chunked_string.putClientProperty('chunked_string_selected_payload_index', payload_index)
            menu_item_un_chunk_chunked_string.putClientProperty('chunked_string_invocation', invocation)

            return [
                menu_item_decoding_grpc_web_text,
                menu_item_encoding_grpc_web_text,
                # menu_item_decoding_grpc_web,
                # menu_item_encoding_grpc_web,
                menu_item_big_string_chunker,
                menu_item_un_chunk_chunked_string,
            ]

    def un_chunk_chunked_string(self, event):
        """
        Un-Chunk chunked string (remove ['"','\n','  '])
        :param event:
        :return:
        """

        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('chunked_string_selected_payload')
        _invocation = menu_item.getClientProperty('chunked_string_invocation')
        _index = menu_item.getClientProperty('chunked_string_selected_payload_index')

        temp_file_path = 'chunked_string.txt'

        with open(temp_file_path, "w") as file:
            file.write(selected_payload.strip())

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"

        command = python_name + " big-string-chunker.py --file chunked_string.txt --un-chunk"

        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        # output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e:
                self.pprint(str(e))

        if output:
            self.update_decoded_request_grpc_web_text(_invocation, _index, output)

        return None

    def chunk_big_string(self, event):
        """
        Chunk big string into pieces of 80 characters using big-string-chunker.py
        :param event:
        :return:
        """

        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('big_string_selected_payload')
        _invocation = menu_item.getClientProperty('big_string_invocation')
        _index = menu_item.getClientProperty('big_string_selected_payload_index')

        temp_file_path = 'big_string.txt'

        with open(temp_file_path, "w") as file:
            file.write(selected_payload.strip())

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"

        command = python_name + " big-string-chunker.py --file big_string.txt --chunk"

        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        # output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e:
                self.pprint(str(e))

        if output:
            self.update_decoded_request_grpc_web_text(_invocation, _index, output)

        return None

    def get_selected_text(self, invocation):
        request_text = invocation.getSelectedMessages()[0].getRequest().tostring().decode('utf-8')

        text_index = invocation.getSelectionBounds()
        start_index = text_index[0]
        end_index = text_index[1]

        selected_text = request_text[start_index:end_index]

        return selected_text

    def get_index_of_selected_text(self, invocation):

        text_index = invocation.getSelectionBounds()
        start_index = text_index[0]
        end_index = text_index[1]

        return (start_index, end_index)

    def update_decoded_request_grpc_web_text(self, invocation, index, new_payload):
        """
        update the request with decoded value
        application/grpc-web-text Content-Type
        :param invocation:
        :param index:
        :param new_payload:
        :return:
        """
        # index is a tuple --> (start_index, end_index)

        old_request_string = invocation.getSelectedMessages()[0].getRequest().tostring()

        new_request_string = old_request_string[:index[0]] + new_payload + old_request_string[index[1] + 1:]
        new_request_bytes = self.helpers.stringToBytes(new_request_string)
        invocation.getSelectedMessages()[0].setRequest(new_request_bytes)

    def update_decoded_request_grpc_web(self, invocation, index, new_payload):
        """
        update the request with decoded value
        application/grpc-web+proto Content-Type
        :param invocation:
        :param index:
        :param new_payload:
        :return:
        """
        # index is a tuple --> (start_index, end_index)

        old_request_string = invocation.getSelectedMessages()[0].getRequest().tostring()

        new_request_string = old_request_string[:index[0]] + new_payload + old_request_string[index[1] + 1:]
        new_request_bytes = self.helpers.stringToBytes(new_request_string)
        invocation.getSelectedMessages()[0].setRequest(new_request_bytes)

    def update_encoded_request_grpc_web_text(self, invocation, index, new_payload):
        """
        update the request with encoded value
        application/grpc-web-text Content-Type
        :param invocation:
        :param index:
        :param new_payload:
        :return:
        """
        # index is a tuple --> (start_index, end_index)

        old_request_string = invocation.getSelectedMessages()[0].getRequest().tostring().decode('utf-8')

        new_request_string = old_request_string[:index[0]] + new_payload + old_request_string[index[1] + 1:]
        new_request_bytes = self.helpers.stringToBytes(new_request_string)
        invocation.getSelectedMessages()[0].setRequest(new_request_bytes)

    def update_encoded_request_grpc_web(self, invocation, index, new_payload):
        """
        update the request with encoded value
        application/grpc-web+proto Content-Type
        :param invocation:
        :param index:
        :param new_payload:
        :return:
        """
        # index is a tuple --> (start_index, end_index)

        old_request_string = invocation.getSelectedMessages()[0].getRequest().tostring().decode('utf-8')

        new_request_string = old_request_string[:index[0]] + new_payload + old_request_string[index[1] + 1:]
        new_request_bytes = self.helpers.stringToBytes(new_request_string)
        invocation.getSelectedMessages()[0].setRequest(new_request_bytes)

    def encode_payload_grpc_web_text(self, event):
        """
        Encode application/grpc-web-text Content-Type
        :param event:
        :return:
        """

        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('grpc_selected_payload')
        _invocation = menu_item.getClientProperty('grpc_encoding_invocation')
        _index = menu_item.getClientProperty('grpc_selected_payload_index')

        temp_file_path_encoding = 'grpc_coder_output_encode.txt'

        try:
            with open(temp_file_path_encoding, "w") as temp_encoding_file:
                temp_encoding_file.write(selected_payload.strip().encode('utf-8'))
        except Exception as e:
            self.pprint(str(e))

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"

        command = grpc_utils.PROTOSCOPE_PATH + " -s grpc_coder_output_encode.txt | " + python_name + " grpc-coder.py --encode"
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path_encoding):
            try:
                os.remove(temp_file_path_encoding)
            except OSError as e:
                self.pprint(str(e))

        if output:
            self.update_encoded_request_grpc_web_text(_invocation, _index, output)

        return None

    def decode_payload_grpc_web_text(self, event):
        """
        Decode application/grpc-web-text Content-Type
        :param event:
        :return:
        """

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

        command = python_name + " grpc-coder.py --decode --file grpc_coder_output_decode.txt | " + grpc_utils.PROTOSCOPE_PATH

        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        # output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e:
                self.pprint(str(e))

        if output:
            self.update_decoded_request_grpc_web_text(_invocation, _index, output)

        return None

    def encode_payload_grpc_web(self, event):
        """
       Encode application/grpc-web+proto Content-Type
       :param event:
       :return:
       """

        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('grpc_selected_payload')
        _invocation = menu_item.getClientProperty('grpc_encoding_invocation')
        _index = menu_item.getClientProperty('grpc_selected_payload_index')

        temp_file_path_encoding = 'grpc_coder_output_encode.txt'

        try:
            with open(temp_file_path_encoding, "w") as temp_encoding_file:
                temp_encoding_file.write(selected_payload.strip())
        except Exception as e:
            self.pprint(str(e))

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"

        command = grpc_utils.PROTOSCOPE_PATH + " -s grpc_coder_output_encode.txt | " + python_name + " grpc-coder.py --encode --type grpc-web+proto"
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path_encoding):
            try:
                os.remove(temp_file_path_encoding)
            except OSError as e:
                self.pprint(str(e))

        if output:
            self.update_encoded_request_grpc_web(_invocation, _index, output)

        return None

    def decode_payload_grpc_web(self, event):
        """
        Decode application/grpc-web+proto Content-Type
        :param event:
        :return:
        """

        menu_item = event.getSource()
        selected_payload = menu_item.getClientProperty('grpc_selected_payload')
        _invocation = menu_item.getClientProperty('grpc_decoding_invocation')
        _index = menu_item.getClientProperty('grpc_selected_payload_index')

        temp_file_path = 'grpc_coder_output_decode.txt'

        with open(temp_file_path, "wb") as file:
            file.write(selected_payload.strip())

        python_name = "python"
        if not System.getProperty('os.name').startswith("Windows"):
            status, _ = commands.getstatusoutput('which python3')
            if status != 0:
                python_name = "python"
            else:
                python_name = "python3"

        command = python_name + " grpc-coder.py --decode --file grpc_coder_output_decode.txt --type grpc-web+proto | " + grpc_utils.PROTOSCOPE_PATH

        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        # output = output.decode('utf-8')
        output = output.strip()

        # Check if the file exists before attempting to remove it
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e:
                self.pprint(str(e))

        if output:
            self.update_decoded_request_grpc_web(_invocation, _index, output)

        return None

    def pprint(self, text):
        self.stdout.println(text)

    def print_error(self, text):
        """
        write error
        :return:
        """
        self.stderr.println(str(text))

