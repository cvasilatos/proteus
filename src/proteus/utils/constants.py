"""Configuration constants for Proteus protocol fuzzer.

This module centralizes hardcoded values and magic numbers to improve maintainability.
"""

# Connection defaults
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5020
DEFAULT_TIMEOUT = 1.0
VALIDATION_TIMEOUT = 0.01

# Mutation testing parameters
DEFAULT_MUTATION_SAMPLE_SIZE = 1000
FUZZABLE_THRESHOLD = 50
CONSTRAINED_THRESHOLD = 10

# Payload generation
STRUCTURAL_VARIANT_PAYLOAD_LENGTHS = [0, 2, 4, 8, 16]
STRUCTURAL_VARIANT_FUNCTION_CODES = ["01", "02", "03", "04", "05", "06"]

# Protocol-specific field names
MODBUS_FUNCTION_CODE_FIELD = "modbus.func_code"

# Packet validation
PACKET_LENGTH_OFFSET = 6

# Response validation
INVALID_RESPONSE_PREFIX = "0000"
ERROR_CODE_SUFFIX = "04"
