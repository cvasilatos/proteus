from __future__ import annotations

import logging
import socket
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from logger_captain.logger import CustomLogger
    from pyshark.packet.fields import LayerField
    from pyshark.packet.layers.base import BaseLayer
    from pyshark.packet.layers.json_layer import JsonLayer

from protocol_validator.validator_base import ProtocolInfo, ValidatorBase

from icsd_surrogate.model.raw_field import FieldBehavior, RawField


class ProtocolExplorer:
    def __init__(self, seed: str, proto_filter: str) -> None:
        logger_name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(logger_name))

        self._seed: str = seed
        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(proto_filter)
        self._raw_fields: list[RawField] = []
        self._validator = ValidatorBase(self._protocol_info.protocol_name)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect(("localhost", self._protocol_info.custom_port))
        self.logger.info(f"[+] Connected to {self._protocol_info.name} server on port {self._protocol_info.custom_port}")

    def validate_seed(self) -> BaseLayer:
        packet: BaseLayer = self._validator.validate(self._seed, is_request=True)
        self._sock.send(bytes.fromhex(self._seed))
        response: bytes = self._sock.recv(1024)
        if len(response) > 0 and response.hex()[0:2] != "0000":
            self.logger.info(f"[+] Dissecting packet: {self._seed} : {response.hex()} for protocol layers: {self._protocol_info.scapy_names}")
        else:
            raise ValueError("No response or unexpected response for packet: {self._seed}, cannot dissect.")

        return packet

    def dissect(self) -> None:
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
        return self._raw_fields


if __name__ == "__main__":
    seed = "ab850000000fb210cab50004087e642f88592c73a6"

    explorer = ProtocolExplorer(seed, "mbtcp")
