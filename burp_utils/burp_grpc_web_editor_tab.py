from burp import IMessageEditorTab
from javax.swing import JTabbedPane, JPanel, JCheckBox, JButton
from java.awt import GridLayout, BorderLayout
from java.awt.event import ActionListener
import traceback
from grpc_coder_withdout_dependency import decode_b64_grpc_web_text, encode_grpc_web_json_to_b64_format
from grpc_coder_withdout_dependency import create_bbpb_type_def_from_json, get_main_json_from_type_def_ordered_dict

class GrpcWebExtensionEditorTab(IMessageEditorTab, ActionListener):  # FIXED: Implement ActionListener
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._is_first_time_tab_opened = True

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
        self._txtInputSettings = JPanel()
        self._txtInputSettings.setLayout(GridLayout(1, 1))
        self._grpcWebTextPayloadCheckBox = JCheckBox("application/grpc-web-text payload ?")
        self._txtInputSettings.add(self._grpcWebTextPayloadCheckBox)
        self._tabbedPane.addTab("Settings", self._txtInputSettings)

    def getTabCaption(self):
        return "Decoded gRPC-Web ProtoBuf"

    def getUiComponent(self):
        return self._tabbedPane

    def isEnabled(self, content, isRequest):
        analyzed_request = self._extender._helpers.analyzeRequest(content)
        req_headers = analyzed_request.getHeaders()
        for h in req_headers:
            if h.lower().startswith('content-type'):
                _, value = h.split(':', 1)
                value = value.strip()
                if value.startswith('application/grpc'):
                    self._grpcWebTextPayloadCheckBox.setSelected(value.startswith('application/grpc-web-text'))
                    return True
            if h.lower().startswith('grpc-x-content-type'):
                _, value2 = h.split(':', 1)
                value2 = value2.strip()
                if value2.startswith('application/grpc'):
                    self._grpcWebTextPayloadCheckBox.setSelected(value2.startswith('application/grpc-web-text'))
                    return True

        return True

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

        if True:
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
            print("[*] Edit mode enabled")

        elif source == self._saveButton:
            content = self._txtInputTypeDef.getText()
            print("[*] Type Definition Saved:", content)
            self._txtInputTypeDef.setEditable(False)
            self._saveButton.setEnabled(False)
            self._isTypeDefinitionEdited = True

        elif source == self._resetButton:
            self._isTypeDefinitionEdited = False
            content = self._txtInputTypeDef.getText()
            self._txtInputTypeDef.setEditable(False)
            self._saveButton.setEnabled(False)
            print("[*] Type Definition is Reset:", content)

    def getMessage(self):
        """ Return the modified content from the payload tab """
        if True:
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
                traceback.print_exc()
                print("Error encoding modified payload:", str(e))


        # Return the original request if no modifications
        return self._currentMessage
