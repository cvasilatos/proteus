"""Packet manipulation utilities for Proteus.

This module provides utilities for packet construction, mutation, and manipulation.
"""

import struct
from proteus.model.raw_field import RawField
from proteus.utils.constants import PACKET_LENGTH_OFFSET


class PacketManipulator:
    """Handles packet construction and manipulation operations."""

    @staticmethod
    def construct_prefix(fields: list[RawField], stop_at_name: str) -> bytes:
        """Construct packet bytes from fields up to a specific field.
        
        Args:
            fields: List of raw fields
            stop_at_name: Name of the field to stop at (not included)
            
        Returns:
            Packet bytes constructed from fields
        """
        prefix = b""
        for field in fields:
            if field.name == stop_at_name:
                break
            prefix += bytes.fromhex(field.val)
        return prefix

    @staticmethod
    def fix_length_field(packet_bytes: bytes, len_field: RawField) -> bytes:
        """Fix length field in packet to match actual packet size.
        
        Note: This includes protocol-specific logic (e.g., Modbus TCP) where
        a zero byte is inserted before the length value and the position
        calculations account for this.
        
        Args:
            packet_bytes: The packet bytes
            len_field: The length field to fix
            
        Returns:
            Updated packet bytes with correct length field
        """
        length_value = len(packet_bytes) - PACKET_LENGTH_OFFSET
        length_bytes = struct.pack(">H", length_value)
        # Protocol-specific: skip one byte, insert zero, then length bytes
        start_pos = len_field.relative_pos + 1
        end_pos = start_pos + len_field.size + 1
        return packet_bytes[:start_pos] + b"\x00" + length_bytes + packet_bytes[end_pos:]

    @staticmethod
    def inject_mutation(
        target_field: RawField,
        base_payload_hex: str,
        mutation_hex: str,
        unique_fields: list[RawField],
    ) -> bytearray:
        """Inject a mutation into a field and update dependent fields (length, CRC).
        
        Args:
            target_field: The field to mutate
            base_payload_hex: Original packet as hex string
            mutation_hex: Mutation value as hex string
            unique_fields: All fields in the packet
            
        Returns:
            Mutated packet as bytearray
        """
        payload_copy = bytearray(bytes.fromhex(base_payload_hex))
        
        # Inject mutation
        start_index = target_field.relative_pos
        end_index = start_index + target_field.size
        payload_copy[start_index:end_index] = bytes.fromhex(mutation_hex)

        # Update length and CRC fields
        payload_copy = PacketManipulator._update_dependent_fields(
            payload_copy, base_payload_hex, target_field, unique_fields
        )
        
        return payload_copy

    @staticmethod
    def _update_dependent_fields(
        payload: bytearray,
        base_payload_hex: str,
        target_field: RawField,
        unique_fields: list[RawField],
    ) -> bytearray:
        """Update length and CRC fields after mutation.
        
        Args:
            payload: Mutated payload
            base_payload_hex: Original packet hex
            target_field: The mutated field
            unique_fields: All fields in the packet
            
        Returns:
            Updated payload with recalculated length and CRC fields
        """
        prev = 0
        for field in unique_fields:
            if ".len" in field.name.lower() and target_field.name != field.name:
                total_bytes = len(base_payload_hex) // 2
                payload_len = total_bytes - PACKET_LENGTH_OFFSET
                start = field.relative_pos
                end = start + field.size
                payload = payload[:start] + payload_len.to_bytes(field.size, byteorder="big") + payload[end:]

            elif "crc" in field.name.lower() and target_field.name != field.name:
                start = field.relative_pos
                end = start + field.size
                crc_value = dnp3_crc_simple(payload[prev:start])
                prev = end
                payload = payload[:start] + crc_value.to_bytes(field.size, byteorder="little") + payload[end:]

        return payload


def dnp3_crc_simple(data_part: bytearray) -> int:
    """Calculate DNP3 CRC for a data segment.
    
    Args:
        data_part: Data to calculate CRC for
        
    Returns:
        CRC value as integer
    """
    crc = 0x0000
    polynomial = 0xA6BC

    for byte in data_part:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ polynomial
            else:
                crc >>= 1

    return (~crc) & 0xFFFF
