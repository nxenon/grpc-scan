from burp import IBurpExtender, IMessageEditorTabFactory
from burp_grpc_web_editor_tab import gRPCWebExtensionEditorTab

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Name of extension
        callbacks.setExtensionName("gRPC-Web Pentest Suite")

    def createNewInstance(self, controller, editable):
        return gRPCWebExtensionEditorTab(self._callbacks, editable)

    def pprint(self, text):
        self._callbacks.printOutput(text)
