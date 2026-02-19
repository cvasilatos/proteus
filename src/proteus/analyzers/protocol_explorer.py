"""Module: protocol_explorer.py.

Description: Implements the ProtocolExplorer class which takes a seed packet and protocol information, validates the seed, dissects it using PyShark,
and extracts raw fields for further analysis. It also handles connection to the target server for validation and response analysis.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast

from praetor.praetord import ProtocolInfo, ValidatorBase

from proteus.model.raw_field import FieldBehavior, RawField
from proteus.utils.response_validator import is_valid_response
from proteus.utils.socket_manager import SocketManager

if TYPE_CHECKING:
    from decimalog.logger import CustomLogger
    from pyshark.packet.fields import LayerField
    from pyshark.packet.layers.base import BaseLayer
    from pyshark.packet.layers.json_layer import JsonLayer


class ProtocolExplorer:
    """Explores a protocol by validating a seed packet, dissecting it to extract raw fields, and preparing the data for dynamic analysis and fuzzing."""

    def __init__(self, packet: str, proto_filter: str) -> None:
        """Initialize the ProtocolExplorer with a seed packet and protocol filter, sets up logging, validates the seed, and prepares for dissection."""
        logger_name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(logger_name))

        self._packet: str = packet
        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(proto_filter)
        self._raw_fields: list[RawField] = []
        self._validator = ValidatorBase(self._protocol_info.protocol_name)

        self._socket_manager = SocketManager("localhost", self._protocol_info.custom_port)
        self._socket_manager.connect()
        self.logger.info(f"[+] Connected to {self._protocol_info.name} server on port {self._protocol_info.custom_port}")

    def validate_seed(self) -> BaseLayer:
        """Validate the seed packet by sending it to the target server and analyzing the response. If a valid response is received, it returns the dissected packet by PyShark."""
        packet: BaseLayer = self._validator.validate(self._packet, is_request=True)
        self._socket_manager.send(bytes.fromhex(self._packet))
        response: bytes = self._socket_manager.receive(1024)

        if is_valid_response(response):
            self.logger.info(f"[+] Dissecting packet: {self._packet} : {response.hex()} for protocol layers: {self._protocol_info.scapy_names}")
        else:
            raise ValueError(f"No response or unexpected response for packet: {self._packet}, cannot dissect.")

        return packet

    def dissect(self) -> None:
        """Dissect the validated seed packet using PyShark to extract raw fields, handling overlapping fields and preparing the data for further analysis."""
        packet: BaseLayer = self.validate_seed()

        threshold = -1
        prev_pos = 0
        layer: JsonLayer
        for layer in packet.layers:
            if layer.layer_name not in self._protocol_info.scapy_names:
                continue

            for field_name in layer.field_names:
                field_or_list: list[LayerField] = layer.get_field(field_name).all_fields
                for f in field_or_list:
                    rf = RawField(
                        display_name=f.showname,
                        name=f.name,
                        wireshark_name=f.name,
                        relative_pos=int(f.pos) - threshold,
                        pos=int(f.pos),
                        size=int(f.size),
                        layer=layer.layer_name,
                        val=f.raw_value,
                    )

                    if threshold == -1:
                        threshold = int(f.pos)

                    if not f.raw_value or not f.name:
                        continue

                    if prev_pos == int(f.pos) and "status" in f.name:
                        self.logger.debug(f"    [!] Overlapping field detected at pos {f.pos}, marking as CALCULATED previous: {self._raw_fields[-1].name}.")
                        self._raw_fields[-1].behavior = FieldBehavior.CALCULATED

                    if prev_pos == int(f.pos):
                        self._raw_fields[-1] = rf
                        self.logger.warning(f"    [!] Skipping..Overlapping field with larger size detected at pos {f.pos}, Value: {f.showname_value}")
                        continue

                    if int(f.pos) >= threshold:
                        self.logger.debug(f"[+] {rf}")
                        self._raw_fields.append(rf)

                    prev_pos = int(f.pos)

        self._raw_fields.sort(key=lambda x: x.pos)
        self.logger.debug(f"[+] Learned {len(self._raw_fields)} fuzzable fields.")

    @property
    def raw_fields(self) -> list[RawField]:
        """Returns the list of raw fields extracted from the dissected packet."""
        return self._raw_fields


if __name__ == "__main__":
    seed = "ab850000000fb210cab50004087e642f88592c73a6"

    explorer = ProtocolExplorer(seed, "mbtcp")
