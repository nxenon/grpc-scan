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
from array import array
import traceback

import grpc_utils


class GrpcInsertionPoint(IScannerInsertionPoint):
    INS_EXTENSION_PROVIDED = 65

    def __init__(self, extender, baseRequest, offset, decodedData, insertionPointName, field_path=None):
        self._extender = extender
        self._baseRequest = baseRequest
        self._offset = offset
        self._originalData = decodedData
        self._insertionPointName = insertionPointName
        self._field_path = field_path or []  # Track the path to this field in nested structure
        self._fullMessage = decodedData

        try:
            print("\nParsing:", decodedData)
            self._baseValue = grpc_utils.extract_value_from_path(self._field_path, decodedData)

        except:
            print("Error parsing gRPC structure in insertion point")
            print(traceback.format_exc())

    def buildRequest(self, payload):
        try:
            if isinstance(payload, array):
                payload = "".join(map(chr, payload))
            elif isinstance(payload, bytes):
                payload = self._extender.helpers.bytesToString(payload)

            print("Building request with payload:", payload)
            print("Current field path:", self._field_path)

            new_message = grpc_utils.replace_value_at_path(self._fullMessage, self._field_path, payload)
            print("Modified message:", new_message)

            encodedPayload = grpc_utils.get_encoded_payload_grpc_web_text(new_message)
            print("Decoded: ", grpc_utils.get_decoded_payload_grpc_web_text(encodedPayload))
            # Validate encoded payload
            if not encodedPayload:
                print("Warning: Empty encoded payload")
                return self._baseRequest

            # Construct the new request
            prefix = self._baseRequest[:self._offset]
            encoded_bytes = self._extender.helpers.stringToBytes(encodedPayload)

            # Build the complete request
            result = prefix + encoded_bytes

            # Add any remaining data after the body if needed
            if self._offset + len(encoded_bytes) < len(self._baseRequest):
                suffix = self._baseRequest[self._offset + len(encoded_bytes):]
                result += suffix

            print("Final request length:", len(result))
            return result

        except Exception as e:
            print("Error building request:", str(e))
            print(traceback.format_exc())
            return self._baseRequest

    def getPayloadOffsets(self, payload):
        print("getPayloadOffsets called with payload:", payload)
        try:
            encoded_base = grpc_utils.get_encoded_payload_grpc_web_text(self._fullMessage)
            base_bytes = self._extender.helpers.stringToBytes(encoded_base)
            start = self._offset
            end = start + len(base_bytes)
            print("Calculated offsets:", [start, end])
            return [start, end]
        except:
            print("Error calculating offsets")
            print(traceback.format_exc())
            return [self._offset, self._offset + len(payload)]

    def getInsertionPointType(self):
        print("getInsertionPointType called, returning:", self.INS_EXTENSION_PROVIDED)
        return INS_EXTENSION_PROVIDED

    def getInsertionPointName(self):
        print("getInsertionPointName called, returning:", self._insertionPointName)
        return self._insertionPointName

    def getBaseValue(self):
        print("getBaseValue called with base value:", self._baseValue)
        return self._baseValue if self._baseValue is not None else ""