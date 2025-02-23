from burp import IMessageEditorTab
from javax.swing import JTabbedPane, JPanel, JCheckBox, JButton
from java.awt import GridLayout, BorderLayout
from java.awt.event import ActionListener
import traceback

import grpc_coder
from grpc_coder_withdout_dependency import decode_b64_grpc_web_text, encode_grpc_web_json_to_b64_format
from grpc_coder_withdout_dependency import decode_grpc_web_proto_payload, encode_grpc_web_proto_json_to_proto_format
from grpc_coder_withdout_dependency import create_bbpb_type_def_from_json, get_main_json_from_type_def_ordered_dict

class GrpcWebExtensionEditorTab(IMessageEditorTab, ActionListener):  # FIXED: Implement ActionListener
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._is_first_time_tab_opened = True

        ## main (general) settings checkboxes from extender class to access the easier
        self._enable_extension_msg_editor_tab_check_box = self._extender._enable_extension_msg_editor_tab_check_box
        self._detect_encode_decode_format_from_ct_header_check_box = self._extender._detect_encode_decode_format_from_ct_header_check_box
        self._detect_encode_decode_format_from_x_grpc_header_check_box = self._extender._detect_encode_decode_format_from_x_grpc_header_check_box
        self._enable_application_grpc_web_text_decode_encode_by_default_check_box = self._extender._enable_application_grpc_web_text_decode_encode_by_default_check_box
        self._enable_application_grpc_web_proto_decode_encode_by_default_check_box = self._extender._enable_application_grpc_web_proto_decode_encode_by_default_check_box
        self._enableGrpcWebTextEncodeDecode = False
        self._enableGrpcWebProtoEncodeDecode = False

        self._tabbedPane = JTabbedPane()

        # Payload Tab
        self._txtInputPayload = extender._callbacks.createTextEditor()
        self._txtInputPayload.setEditable(editable)
        self._tabbedPane.addTab("Payload", self._txtInputPayload.getComponent())

        # Type Definition Tab
        self._txtInputTypeDef = extender._callbacks.createTextEditor()
        self._txtInputTypeDef.setEditable(False)

        self._typeDefPanel = JPanel()
        self._typeDefPanel.setLayout(BorderLayout())

        # Buttons for Type Definition
        self._editButton = JButton("Edit Type Definition", actionPerformed=self.actionPerformed)
        self._saveButton = JButton("Save Type Definition", actionPerformed=self.actionPerformed)
        self._resetButton = JButton("Reset Type Definition (Auto)", actionPerformed=self.actionPerformed)
        self._saveButton.setEnabled(False)
        self._isTypeDefinitionEdited = False

        # Add editor to the Type Definition panel
        self._typeDefPanel.add(self._txtInputTypeDef.getComponent(), BorderLayout.CENTER)

        # Create button panel
        self._buttonPanel = JPanel()
        self._buttonPanel.add(self._editButton)
        self._buttonPanel.add(self._saveButton)
        self._buttonPanel.add(self._resetButton)

        # Add button panel to the bottom of Type Definition tab
        self._typeDefPanel.add(self._buttonPanel, BorderLayout.SOUTH)
        self._tabbedPane.addTab("Type Definition", self._typeDefPanel)

        # Settings Tab
        # self._txtInputSettings = JPanel()
        # self._txtInputSettings.setLayout(GridLayout(1, 1))
        # self._grpcWebTextPayloadCheckBox = JCheckBox("application/grpc-web-text payload ?")
        # self._txtInputSettings.add(self._grpcWebTextPayloadCheckBox)
        # self._tabbedPane.addTab("Settings", self._txtInputSettings)

    def print_output(self, text):
        self._extender.print_output(text)

    def print_error(self, text):
        self._extender.print_error(text)

    def getTabCaption(self):
        return "Decoded gRPC-Web ProtoBuf"

    def getUiComponent(self):
        return self._tabbedPane

    def isEnabled(self, content, isRequest):
        if self._enable_application_grpc_web_text_decode_encode_by_default_check_box.isSelected():
            self._enableGrpcWebProtoEncodeDecode = False
            self._enableGrpcWebTextEncodeDecode = True
            return True

        if self._enable_application_grpc_web_proto_decode_encode_by_default_check_box.isSelected():
            self._enableGrpcWebTextEncodeDecode = False
            self._enableGrpcWebProtoEncodeDecode = True
            return True

        __isEnabled = False
        analyzed_request = self._extender._helpers.analyzeRequest(content)
        req_headers = analyzed_request.getHeaders()

        if self._enable_extension_msg_editor_tab_check_box.isSelected():
            __isEnabled = True

        if (self._detect_encode_decode_format_from_ct_header_check_box.isSelected() or
                self._detect_encode_decode_format_from_x_grpc_header_check_box.isSelected()):
            for h in req_headers:
                if self._detect_encode_decode_format_from_ct_header_check_box.isSelected():
                    if h.lower().startswith('content-type'):
                        _, value = h.split(':', 1)
                        value = value.strip()
                        if value.startswith('application/grpc-web-text'):
                            self._enableGrpcWebTextEncodeDecode = True
                            __isEnabled = True
                        elif value.startswith('application/grpc-web+proto'):
                            self._enableGrpcWebProtoEncodeDecode = True
                            __isEnabled = True

                elif self._detect_encode_decode_format_from_x_grpc_header_check_box.isSelected():
                    if h.lower().startswith('x-grpc-content-type'):
                        _, value2 = h.split(':', 1)
                        value2 = value2.strip()
                        if value2.startswith('application/grpc-web-text'):
                            self._enableGrpcWebTextEncodeDecode = True
                            __isEnabled = True
                        elif value2.startswith('application/grpc-web+proto'):
                            self._enableGrpcWebProtoEncodeDecode = True
                            __isEnabled = True

        return __isEnabled

    def isModified(self):
        """ Check if either tab content is modified """
        return self._txtInputPayload.isTextModified() or self._txtInputTypeDef.isTextModified()

    def isGrpcWebTextPayloadEnabled(self):
        """ Returns whether the checkbox is checked """
        return self._grpcWebTextPayloadCheckBox.isSelected()

    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInputPayload.setText(None)
            self._txtInputPayload.setEditable(False)
            self._txtInputTypeDef.setText(None)
            self._txtInputTypeDef.setEditable(False)
            return

        if self._enableGrpcWebTextEncodeDecode:
            analyzed_request = self._extender._helpers.analyzeRequest(content)
            body_offset = analyzed_request.getBodyOffset()
            request_body = content[body_offset:]

            try:
                message, typedef = decode_b64_grpc_web_text(payload=request_body)
                decoded_string = message.decode("unicode_escape")
                message = decoded_string
                message = message.encode('utf-8')
                typedef_main_json = get_main_json_from_type_def_ordered_dict(type_def=typedef)
            except Exception as e:
                message = "Error decoding request: {}".format(str(e))
                typedef_main_json = "No Type Definition"
                self.print_error(message)

            self._txtInputPayload.setText(message)
            self._txtInputPayload.setEditable(self._editable)

            if not self._isTypeDefinitionEdited:
                self._txtInputTypeDef.setText(str(typedef_main_json))
                self._txtInputTypeDef.setEditable(False)

        elif self._enableGrpcWebProtoEncodeDecode:
            analyzed_request = self._extender._helpers.analyzeRequest(content)
            body_offset = analyzed_request.getBodyOffset()
            request_body = content[body_offset:]
            request_body = request_body.tostring()
            request_body = request_body.decode('utf-8', errors='surrogatepass')
            # request_body = request_body.decode("unicode_escape")

            try:
                message, typedef = decode_grpc_web_proto_payload(payload=request_body)
                decoded_string = message.decode("unicode_escape")
                message = decoded_string
                message = message.encode('utf-8')
                typedef_main_json = get_main_json_from_type_def_ordered_dict(type_def=typedef)
            except Exception as e:
                message = "Error decoding request: {}".format(str(e))
                typedef_main_json = "No Type Definition"
                self.print_error(message)

            self._txtInputPayload.setText(message)
            self._txtInputPayload.setEditable(self._editable)

            if not self._isTypeDefinitionEdited:
                self._txtInputTypeDef.setText(str(typedef_main_json))
                self._txtInputTypeDef.setEditable(False)

        self._currentMessage = content

    def actionPerformed(self, event):
        """ Handle button clicks """
        source = event.getSource()
        if source == self._editButton:
            self._txtInputTypeDef.setEditable(True)
            self._saveButton.setEnabled(True)
            self.print_output("[*] Edit mode enabled")

        elif source == self._saveButton:
            content = self._txtInputTypeDef.getText()
            self.print_output("[*] Type Definition Saved")
            self._txtInputTypeDef.setEditable(False)
            self._saveButton.setEnabled(False)
            self._isTypeDefinitionEdited = True

        elif source == self._resetButton:
            self._isTypeDefinitionEdited = False
            content = self._txtInputTypeDef.getText()
            self._txtInputTypeDef.setEditable(False)
            self._saveButton.setEnabled(False)
            self.print_output("[*] Type Definition is Reset")

    def getMessage(self):
        """ Return the modified content from the payload tab """
        if self._enableGrpcWebTextEncodeDecode:
            try:
                modified_payload = self._txtInputPayload.getText()  # Get modified text
                modified_payload = modified_payload.tostring()
                # modified_payload = modified_payload.decode('utf-8')
                type_def_raw = self._txtInputTypeDef.getText().tostring().decode('utf-8')
                type_def_object = create_bbpb_type_def_from_json(type_def_raw)
                encoded_payload = encode_grpc_web_json_to_b64_format(modified_payload, type_def_object)  # Convert back

                # Get original request headers
                original_request = self._extender._helpers.analyzeRequest(self._currentMessage)
                headers = original_request.getHeaders()

                # Construct the new request
                new_request = self._extender._helpers.buildHttpMessage(headers, encoded_payload)
                return new_request

            except Exception as e:
                self.print_error("Error encoding modified payload:" +  str(e))

        elif self._enableGrpcWebProtoEncodeDecode:
            try:
                modified_payload = self._txtInputPayload.getText()  # Get modified text
                modified_payload = modified_payload.tostring()
                # modified_payload = modified_payload.decode('utf-8')
                type_def_raw = self._txtInputTypeDef.getText().tostring().decode('utf-8')
                type_def_object = create_bbpb_type_def_from_json(type_def_raw)
                encoded_payload = encode_grpc_web_proto_json_to_proto_format(modified_payload, type_def_object)  # Convert back
                encoded_payload = bytes(encoded_payload)

                # Get original request headers
                original_request = self._extender._helpers.analyzeRequest(self._currentMessage)
                headers = original_request.getHeaders()

                # Construct the new request
                new_request = self._extender._helpers.buildHttpMessage(headers, encoded_payload)
                return new_request

            except Exception as e:
                self.print_error("Error encoding modified payload:" +  str(e))

        # Return the original request if no modifications
        return self._currentMessage
