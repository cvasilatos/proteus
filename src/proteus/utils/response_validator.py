"""Response validation utilities for Proteus.

This module provides common functions for validating server responses
to avoid code duplication across multiple modules.
"""

from proteus.utils.constants import ERROR_CODE_SUFFIX, INVALID_RESPONSE_PREFIX


def is_valid_response(response: bytes) -> bool:
    """Check if a server response is valid and meaningful.

    A response is considered valid if:
    - It's not empty
    - It doesn't start with all-zero bytes (invalid header)
    - It doesn't end with only an error code

    Args:
        response: The response bytes from the server

    Returns:
        True if the response is valid, False otherwise
    """
    if len(response) == 0:
        return False

    response_hex = response.hex()

    # Check for invalid header (all zeros)
    if response_hex[:len(INVALID_RESPONSE_PREFIX)] == INVALID_RESPONSE_PREFIX:
        return False

    # Check if response is just an error code
    if response_hex[-len(ERROR_CODE_SUFFIX):] == ERROR_CODE_SUFFIX and len(response_hex) <= 4:
        return False

    return True
