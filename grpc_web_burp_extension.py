from burp import IBurpExtender, IMessageEditorTabFactory, ITab
from java.io import PrintWriter
from javax.swing import JPanel, JCheckBox, JLabel, BoxLayout
from java.awt.event import ActionListener
from burp_utils.burp_grpc_web_editor_tab import GrpcWebExtensionEditorTab


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab, ActionListener):
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

        # Create and register a new UI tab
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))

        features_label = JLabel("------ Features ------")

        self._enable_extension_msg_editor_tab_check_box = JCheckBox("Enable Extension Message Editor gRPC-Web Tab by "
                                                                    "Default on "
                                                                    "all Requests")
        self._enable_extension_msg_editor_tab_check_box.addActionListener(self)
        self._enable_extension_msg_editor_tab_check_box.setSelected(True)
        self._detect_encode_decode_format_from_ct_header_check_box = JCheckBox("Detect Encode/Decode format from "
                                                                               "Content-Type header (with value of "
                                                                               "application/grpc-web-text or "
                                                                               "application/grpc-web+proto)")
        self._detect_encode_decode_format_from_ct_header_check_box.addActionListener(self)
        self._detect_encode_decode_format_from_ct_header_check_box.setSelected(True)
        self._detect_encode_decode_format_from_x_grpc_header_check_box = JCheckBox("Detect Encode/Decode format from "
                                                                                   "x-grpc-content-type header (with "
                                                                                   "value of "
                                                                                   "application/grpc-web-text or "
                                                                                   "application/grpc-web+proto)")

        self._detect_encode_decode_format_from_x_grpc_header_check_box.addActionListener(self)
        self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(False)
        content_type_note_label = JLabel("------ If you enable following checkbox, extension tries to decode/encode "
                                         "the body on every request ------")
        self._enable_application_grpc_web_text_decode_encode_by_default_check_box = JCheckBox("Enable "
                                                                                              "application/grpc-web"
                                                                                              "-text Decode/Encode by "
                                                                                              "default on all requests")
        self._enable_application_grpc_web_text_decode_encode_by_default_check_box.addActionListener(self)

        self._enable_application_grpc_web_proto_decode_encode_by_default_check_box = JCheckBox("Enable "
                                                                                              "application/grpc-web"
                                                                                              "+proto Decode/Encode by "
                                                                                              "default on all requests")
        self._enable_application_grpc_web_proto_decode_encode_by_default_check_box.addActionListener(self)

        # Add components to panel
        self._panel.add(features_label)
        self._panel.add(self._enable_extension_msg_editor_tab_check_box)
        self._panel.add(self._detect_encode_decode_format_from_ct_header_check_box)
        self._panel.add(self._detect_encode_decode_format_from_x_grpc_header_check_box)
        self._panel.add(content_type_note_label)
        self._panel.add(self._enable_application_grpc_web_text_decode_encode_by_default_check_box)
        self._panel.add(self._enable_application_grpc_web_proto_decode_encode_by_default_check_box)

        # Register the new tab
        callbacks.addSuiteTab(self)

        # Handle checkbox clicks
    def actionPerformed(self, event):
        source = event.getSource()
        if source == self._enable_extension_msg_editor_tab_check_box:
            pass

        elif source == self._detect_encode_decode_format_from_ct_header_check_box:
            if self._detect_encode_decode_format_from_ct_header_check_box.isSelected():
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(False)
            else:
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(True)

        elif source == self._detect_encode_decode_format_from_x_grpc_header_check_box:
            if self._detect_encode_decode_format_from_x_grpc_header_check_box.isSelected():
                self._detect_encode_decode_format_from_ct_header_check_box.setEnabled(False)
            else:
                self._detect_encode_decode_format_from_ct_header_check_box.setEnabled(True)

        elif source == self._enable_application_grpc_web_text_decode_encode_by_default_check_box:
            if self._enable_application_grpc_web_text_decode_encode_by_default_check_box.isSelected():
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setSelected(False)
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(False)

                self._detect_encode_decode_format_from_ct_header_check_box.setSelected(False)
                self._detect_encode_decode_format_from_ct_header_check_box.setEnabled(False)

                self._enable_extension_msg_editor_tab_check_box.setSelected(True)
                self._enable_extension_msg_editor_tab_check_box.setEnabled(False)

                self._enable_application_grpc_web_proto_decode_encode_by_default_check_box.setSelected(False)
                self._enable_application_grpc_web_proto_decode_encode_by_default_check_box.setEnabled(False)

            else:
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(True)
                self._detect_encode_decode_format_from_ct_header_check_box.setEnabled(True)

                self._enable_extension_msg_editor_tab_check_box.setSelected(True)
                self._enable_extension_msg_editor_tab_check_box.setEnabled(True)

                self._enable_application_grpc_web_proto_decode_encode_by_default_check_box.setEnabled(True)

        elif source == self._enable_application_grpc_web_proto_decode_encode_by_default_check_box:
            if self._enable_application_grpc_web_proto_decode_encode_by_default_check_box.isSelected():
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setSelected(False)
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(False)

                self._detect_encode_decode_format_from_ct_header_check_box.setSelected(False)
                self._detect_encode_decode_format_from_ct_header_check_box.setEnabled(False)

                self._enable_extension_msg_editor_tab_check_box.setSelected(True)
                self._enable_extension_msg_editor_tab_check_box.setEnabled(False)

                self._enable_application_grpc_web_text_decode_encode_by_default_check_box.setSelected(False)
                self._enable_application_grpc_web_text_decode_encode_by_default_check_box.setEnabled(False)
            else:
                self._detect_encode_decode_format_from_x_grpc_header_check_box.setEnabled(True)
                self._detect_encode_decode_format_from_ct_header_check_box.setEnabled(True)

                self._enable_extension_msg_editor_tab_check_box.setSelected(True)
                self._enable_extension_msg_editor_tab_check_box.setEnabled(True)

                self._enable_application_grpc_web_text_decode_encode_by_default_check_box.setEnabled(True)

    def getTabCaption(self):
        return "gRPC-Web Pentest Suite"

    def getUiComponent(self):
        return self._panel

    def createNewInstance(self, controller, editable):
        return GrpcWebExtensionEditorTab(self, controller, editable)

    def print_output(self, text):
        self.stdout.println(text)

    def print_error(self, text):
        self.stderr.println(text)
