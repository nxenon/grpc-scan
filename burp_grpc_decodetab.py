from burp import IBurpExtender
from burp import IContextMenuFactory, IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JMenuItem
from java.lang import System
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IIntruderPayloadProcessor

import grpc_utils


class ProtoDecodeTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable, helpers):
        self._extender = extender
        self._editable = editable

        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self._current_payload = ""

        self.stdout = PrintWriter(extender._callbacks.getStdout(), True)
        self.stderr = PrintWriter(extender._callbacks.getStderr(), True)

    #
    # implement IMessageEditorTab
    #
    def pprint(self, text):
        self.stdout.println(text)

    def getTabCaption(self):
        return "Decoded Protobuf"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a data parameter
        return True

    def setMessage(self, content, isRequest):
        if (content is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            # retrieve the serialized data
            requestInfo = self._extender.helpers.analyzeRequest(content)
            headers = requestInfo.getHeaders()
            msgBody = content[requestInfo.getBodyOffset():]

            newHeaders = list(headers)

            if not len(newHeaders) > 0:
                print("No headers")
                print(newHeaders)
                return

            query_line = newHeaders[0]

            if " " not in query_line:
                print("No space in query line? ")
                print(query_line)
                return

            # build a new http message
            method = query_line.split(" ")[0]

            msgBody = self._extender.helpers.bytesToString(msgBody)
            decodedData = grpc_utils.get_decoded_payload_grpc_web_text(msgBody)
            self._current_payload = decodedData
            # deserialize the parameter value
            self._txtInput.setText(decodedData)
            self._txtInput.setEditable(self._editable)

        # remember the displayed content
        self._currentMessage = content
        return

    def getMessage(self):
        # determine whether the user modified the deserialized data
        if (self._txtInput.isTextModified()):
            payload = self._txtInput.getText()
            payload = self._extender.helpers.bytesToString(payload)
            encoded_data = grpc_utils.get_encoded_payload_grpc_web_text(str(payload))
            requestInfo = self._extender.helpers.analyzeRequest(self._currentMessage)
            content = self._currentMessage[:requestInfo.getBodyOffset()]

            new_request_bytes = self._extender.helpers.stringToBytes(encoded_data)
            content = content + new_request_bytes
            return content
        else:
            return self._currentMessage

    def isModified(self):

        return self._txtInput.isTextModified()

    def getSelectedData(self):

        return self._txtInput.getSelectedText()