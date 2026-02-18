"""Module: dynamic_field_analyzer.py.

Description: Implements the DynamicFieldAnalyzer class which performs dynamic analysis on protocol fields by injecting
mutations and observing server responses to classify field behavior. This includes generating random mutations, sending them to the server,
"""

import difflib
import logging
import random
from typing import TYPE_CHECKING, Any, cast

import plotly.graph_objects as go
from praetor.praetord import ValidatorBase
from praetor.protocol_info import ProtocolInfo

from proteus.model.raw_field import FieldBehavior, RawField
from proteus.utils.constants import CONSTRAINED_THRESHOLD, DEFAULT_MUTATION_SAMPLE_SIZE, FUZZABLE_THRESHOLD, MODBUS_FUNCTION_CODE_FIELD
from proteus.utils.response_validator import is_valid_response
from proteus.utils.socket_manager import SocketManager

if TYPE_CHECKING:
    from decimalog.logger import CustomLogger


class DynamicFieldAnalyzer:
    """Performs dynamic analysis on protocol fields by injecting mutations and observing server responses to classify field behavior."""

    def __init__(self, protocol: str) -> None:
        """Initialize the DynamicFieldAnalyzer with protocol information and sets up a connection to the target server."""
        logger_name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(logger_name))

        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self._validator = ValidatorBase(protocol)
        
        self._socket_manager = SocketManager("localhost", self._protocol_info.custom_port)
        self._socket_manager.connect()
        self.logger.info(f"Connecting to {self._protocol_info.protocol_name} server at localhost:{self._protocol_info.custom_port}")

        self._requests: list[str] = []
        self._responses: list[str] = []

    def _get_random_combinations(self, num_bytes: int, sample_size: int = DEFAULT_MUTATION_SAMPLE_SIZE) -> list[tuple[int, ...]]:
        total_possibilities: int = 256**num_bytes
        sample_size = min(sample_size, total_possibilities)
        self.logger.trace(f"Generating {sample_size} random byte combinations for {num_bytes}-byte field")

        return [tuple(random.choices(range(256), k=num_bytes)) for _ in range(sample_size)]

    def cluster_responses_plotly(self, seed_hex: str) -> None:
        """Cluster responses based on similarity to the seed packet and visualize using Plotly to identify potential exceptions or valid variations."""
        self.logger.info(f"Clustering responses for seed: {seed_hex} with {len(self._responses)} responses and {len(self._requests)} requests...")
        data: list[dict[str, Any]] = []

        seed_bytes: bytes = bytes.fromhex(seed_hex)
        seed_len: int = len(seed_bytes)
        self.logger.debug(f"Analyzing seed packet: length={seed_len} bytes")
        data.append({"hex": seed_hex, "length": seed_len, "similarity": 1.0, "type": "Seed (Valid)", "color": "gold", "size": 20})

        self.logger.debug(f"Analyzing {len(self._requests)} request packets")
        for req in self._requests:
            req_bytes: bytes = bytes.fromhex(req)
            curr_len: int = len(req_bytes)

            matcher: difflib.SequenceMatcher[str] = difflib.SequenceMatcher(None, seed_hex, req)
            ratio: int | float = matcher.ratio()
            self.logger.trace(f"Request packet: length={curr_len}, similarity={ratio:.3f}")

            data.append(
                {
                    "hex": req,
                    "length": curr_len,
                    "similarity": ratio,
                    "type": "Request (Sent)",
                    "color": "orchid",
                    "size": 8,
                }
            )

        self.logger.debug(f"Analyzing {len(self._responses)} response packets")
        for resp in self._responses:
            resp_bytes: bytes = bytes.fromhex(resp)
            curr_len: int = len(resp_bytes)

            matcher: difflib.SequenceMatcher[str] = difflib.SequenceMatcher(None, seed_hex, resp)
            ratio: int | float = matcher.ratio()

            if curr_len <= (seed_len * 0.6):
                category = "Likely Exception"
                color = "crimson"
                size = 12
                self.logger.trace(f"Classified as exception: length={curr_len} (<60% of seed)")
            elif ratio > 0.85:
                category = "Valid Variation"
                color = "mediumseagreen"
                size = 10
                self.logger.trace(f"Classified as valid variation: similarity={ratio:.3f}")
            else:
                category = "Unknown / Outlier"
                color = "royalblue"
                size = 8
                self.logger.trace(f"Classified as outlier: length={curr_len}, similarity={ratio:.3f}")

            data.append(
                {
                    "hex": resp,
                    "length": curr_len,
                    "similarity": ratio,
                    "type": category,
                    "color": color,
                    "size": size,
                }
            )

        self.logger.info("Building plotly visualization with categorized data points")
        fig = go.Figure()

        for cat in ["Seed (Valid)", "Request (Sent)", "Likely Exception", "Valid Variation", "Unknown / Outlier"]:
            subset = [d for d in data if d["type"] == cat]
            if not subset:
                continue

            self.logger.debug(f"Adding trace for category '{cat}' with {len(subset)} data points")
            fig.add_trace(
                go.Scatter(
                    x=[d["length"] for d in subset],
                    y=[d["similarity"] for d in subset],
                    mode="markers",
                    name=cat,
                    marker=dict(color=[d["color"] for d in subset], size=[d["size"] for d in subset], line=dict(width=1, color="DarkSlateGrey")),
                    text=[f"HEX: {d['hex']}" for d in subset],
                    hovertemplate="<b>%{text}</b><br><br>Length: %{x:.1f} bytes<br>Similarity: %{y:.2f}<br><extra></extra>",
                )
            )

        self.logger.info("Applying layout styling and displaying plot")
        fig.update_layout(
            title="Protocol Response Clustering (Exception Identification)",
            xaxis_title="Response Length (Bytes)",
            yaxis_title="Structural Similarity to Seed (0-1)",
            template="plotly_white",
            legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
            height=600,
        )

        self.logger.info(f"Plot summary - Requests: {len(self._requests)}, Responses: {len(self._responses)}")
        fig.show()

    def analyze(self, seed: str, unique_fields: list[RawField]) -> None:
        """Perform dynamic analysis.

        Injecting mutations into the seed packet for each unique field, sending the mutated packets to the server,
        and classifying field behavior based on the responses received.

        This method iterates through each field, generates random mutations, and observes how the server responds to determine if the field is fuzzable, constrained, or calculated.
        """
        self.logger.info(f"[?] Starting Dynamic Analysis on {len(unique_fields)} unique fields...\n")

        for f in unique_fields:
            if f.behavior == FieldBehavior.CALCULATED:
                continue

            self.logger.info(f"[MUTATION] Field: {f}")

            f.valid_values: list[str] = []
            for mutation_hex_tuple in self._get_random_combinations(f.size):
                mutation_hex: str = "".join(f"{b:02x}" for b in mutation_hex_tuple)

                self.logger.debug(f"    [*] Field: {f.name}, testing mutation value: {mutation_hex}, original: {seed[f.relative_pos * 2 : (f.relative_pos + f.size) * 2]}")
                
                try:
                    mutated_hex: str = self._inject_mutation(f, seed, mutation_hex, unique_fields=unique_fields).hex()
                    self._validator.validate(mutated_hex, is_request=True)
                    self._socket_manager.send(bytes.fromhex(mutated_hex))
                    self._requests.append(mutated_hex)
                    response: bytes = self._socket_manager.receive(1024)
                    self._responses.append(response.hex())

                    if is_valid_response(response):
                        self.logger.debug(f"    [OK] Field: {f.name}, Mutation Accepted: {mutation_hex}, Response: {response.hex()}")
                        f.valid_values.append(mutation_hex)

                except Exception as e:
                    self.logger.trace(f"    [ERROR] Exception during mutation testing: {e}")
                    if f.invalid_values.get(str(e)) is None:
                        f.invalid_values[str(e)] = []
                    f.invalid_values[str(e)].append(mutation_hex)
                    
                    # Reconnect on error
                    self._socket_manager.reconnect()

                # Classify field behavior based on valid/invalid response patterns
                if len(f.valid_values) > FUZZABLE_THRESHOLD:
                    f.set_behavior(FieldBehavior.FUZZABLE)
                    f.accepted = True
                    break
                if f.get_biggest_invalid_category_size() > CONSTRAINED_THRESHOLD and len(f.valid_values) == 0:
                    self.logger.info(f"    [!] Field {f.name} has a large invalid category, marking as CONSTRAINED.")
                    f.set_behavior(FieldBehavior.CONSTRAINED)
                    break
                if len(f.valid_values) > 0:
                    self.logger.info(f"    [*] Field {f.name} valid values count: {len(f.valid_values)}, largest invalid category size: {f.get_biggest_invalid_category_size()}")
                    f.set_behavior(FieldBehavior.FUZZABLE)
                    break

        self._run_additional_mutations(unique_fields, seed)

    def _run_additional_mutations(self, unique_fields: list[RawField], seed: str) -> None:
        """Run additional protocol-specific mutation tests.
        
        Args:
            unique_fields: List of fields to test
            seed: Original seed packet hex string
        """
        for f in unique_fields:
            if f.name == MODBUS_FUNCTION_CODE_FIELD:
                for _ in range(100):
                    new_hex = "ff"
                    mutated_hex = self._inject_mutation(f, seed, new_hex, unique_fields=unique_fields).hex()
                    self._socket_manager.send(bytes.fromhex(mutated_hex))
                    response = self._socket_manager.receive(1024)
                    self.logger.info(f"Testing func_code mutation: {mutated_hex}, Response: {response.hex()}")
                    self._responses.append(response.hex())

    def _inject_mutation(self, target_field: RawField, base_payload_bytes: str, mutation_hex: str, unique_fields: list[RawField]) -> bytearray:
        self.logger.trace(f"Injecting mutation {mutation_hex} into field {target_field.name}")
        payload_copy = bytearray(bytes.fromhex(base_payload_bytes))

        start_index = target_field.relative_pos
        end_index = start_index + target_field.size

        payload_copy[start_index:end_index] = bytes.fromhex(mutation_hex)

        prev = 0
        for crc in unique_fields:
            if ".len" in crc.name.lower() and target_field.name != crc.name:
                total_bytes = len(base_payload_bytes) // 2
                payload_len = total_bytes - 6
                start_crc = crc.relative_pos
                end_crc = start_crc + crc.size
                orig = payload_copy[start_crc:end_crc]
                payload_copy = payload_copy[:start_crc] + payload_len.to_bytes(crc.size, byteorder="big") + payload_copy[end_crc:]
                self.logger.trace(
                    f"    [*] Recalculating Length field: {crc.name} at pos {crc.relative_pos} size {crc.size}, prev: {orig.hex()},"
                    f"calculated: {payload_len.to_bytes(crc.size, byteorder='little').hex()}"
                )

            if "crc" in crc.name.lower() and target_field.name != crc.name:
                self.logger.trace(f"    [*] Recalculating CRC field: {crc.name} at pos {crc.relative_pos} size {crc.size}")
                start_crc = crc.relative_pos
                end_crc = start_crc + crc.size
                crc_value = _dnp3_crc_simple(payload_copy[prev:start_crc])
                prev = end_crc
                self.logger.trace(f"New crc start: {start_crc} end: {end_crc} value: {crc_value:#04x}")
                payload_copy = payload_copy[:start_crc] + crc_value.to_bytes(crc.size, byteorder="little") + payload_copy[end_crc:]

        return payload_copy


def _dnp3_crc_simple(data_part: bytearray) -> int:
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
