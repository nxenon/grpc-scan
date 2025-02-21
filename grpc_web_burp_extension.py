from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from java.io import PrintWriter
from burp_utils.burp_grpc_web_editor_tab import GrpcWebExtensionEditorTab


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Name of extension
        callbacks.setExtensionName("gRPC-Web Pentest Suite")

        # Set stdout and stderr
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # Register TabFactory
        callbacks.registerMessageEditorTabFactory(self)


    def createNewInstance(self, controller, editable):
        return GrpcWebExtensionEditorTab(self, controller, editable)

    def print_output(self, text):
        self.stdout.println(text)

    def print_error(self, text):
        self.stderr(text)
