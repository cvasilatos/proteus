import logging
import random
import socket
from typing import TYPE_CHECKING, Any, cast

from icsd_surrogate.model.raw_field import FieldBehavior, RawField

if TYPE_CHECKING:
    from icsd_surrogate.cfg.log_configuration import CustomLogger

import difflib

import plotly.graph_objects as go
from protocol_validator.protocol_info import ProtocolInfo
from protocol_validator.validator_base import ValidatorBase


class DynamicFieldAnalyzer:
    def __init__(self, protocol: str) -> None:
        logger_name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(logger_name))

        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)

        self._validator = ValidatorBase(protocol)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(1)
        self.logger.info(f"Connecting to {self._protocol_info.protocol_name} server at localhost:{self._protocol_info.custom_port}")
        self._sock.connect(("localhost", self._protocol_info.custom_port))

        self._responses: list[str] = []

    def get_random_combinations(self, num_bytes: int, sample_size: int) -> list[tuple[int, ...]]:
        total_possibilities: int = 256**num_bytes

        sample_size: int = min(sample_size, total_possibilities)

        results = []
        for _ in range(sample_size):
            combo = tuple(random.choices(range(256), k=num_bytes))
            results.append(combo)

        return results

    def analyze_responses(self) -> None:
        self.logger.info("Response distribution from server:")
        for response_hex in self._responses:
            count: int = self._responses.count(response_hex)
            self.logger.info(f"Response: {response_hex}, Count: {count}")

    def cluster_responses_plotly(self, seed_hex: str) -> None:
        self.logger.info(f"Clustering responses for seed: {seed_hex} with {len(self._responses)} unique responses...")
        data: list[dict[str, Any]] = []

        # 1. Analyze the Seed
        try:
            seed_bytes: bytes = bytes.fromhex(seed_hex)
            seed_len: int = len(seed_bytes)
            # Add Seed to dataset (as the baseline)
            data.append({"hex": seed_hex, "length": seed_len, "similarity": 1.0, "type": "Seed (Valid)", "color": "gold", "size": 20})
        except ValueError:
            print("Error: Seed is not valid hex.")
            return

        # 2. Analyze the Mutations
        for resp in self._responses:
            try:
                # Convert to bytes for accurate length
                resp_bytes = bytes.fromhex(resp)
                curr_len = len(resp_bytes)

                # Calculate Structural Similarity
                matcher = difflib.SequenceMatcher(None, seed_hex, resp)
                ratio = matcher.ratio()

                # Classification Logic
                # --------------------
                # EXCEPTION: Usually fixed, short length (e.g., < 60% of seed)
                if curr_len <= (seed_len * 0.6):
                    category = "Likely Exception"
                    color = "crimson"
                    size = 12
                # VALID VARIATION: High similarity, length matches seed
                elif ratio > 0.85:
                    category = "Valid Variation"
                    color = "mediumseagreen"
                    size = 10
                # UNKNOWN: Weird length or middle-ground similarity
                else:
                    category = "Unknown / Outlier"
                    color = "royalblue"
                    size = 8

                # Add 'Jitter' to avoid dots stacking perfectly on top of each other
                # (Protocol responses often have identical length/similarity)
                # jitter_x = random.uniform(-0.15, 0.15)
                # jitter_y = random.uniform(-0.02, 0.02)

                data.append(
                    {
                        "hex": resp,
                        "length": curr_len,  # + jitter_x,
                        "similarity": ratio,  # + jitter_y,
                        "type": category,
                        "color": color,
                        "size": size,
                    }
                )

            except ValueError:
                continue  # Skip bad hex

        # 3. Build the Plotly Graph
        fig = go.Figure()

        # We plot by category so we can toggle them in the legend
        for cat in ["Seed (Valid)", "Likely Exception", "Valid Variation", "Unknown / Outlier"]:
            subset = [d for d in data if d["type"] == cat]
            if not subset:
                continue

            fig.add_trace(
                go.Scatter(
                    x=[d["length"] for d in subset],
                    y=[d["similarity"] for d in subset],
                    mode="markers",
                    name=cat,
                    marker=dict(color=[d["color"] for d in subset], size=[d["size"] for d in subset], line=dict(width=1, color="DarkSlateGrey")),
                    # Custom Hover Text: Show the first 30 chars of the HEX string
                    text=[f"HEX: {d['hex']}" for d in subset],
                    hovertemplate="<b>%{text}</b><br><br>Length: %{x:.1f} bytes<br>Similarity: %{y:.2f}<br><extra></extra>",
                )
            )

        # 4. Styling
        fig.update_layout(
            title="Protocol Response Clustering (Exception Identification)",
            xaxis_title="Response Length (Bytes)",
            yaxis_title="Structural Similarity to Seed (0-1)",
            template="plotly_white",
            legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
            height=600,
        )

        print(f"Responses: {self._responses}")
        fig.show()

    def analyze(self, seed: str, unique_fields: list[RawField]) -> None:
        self.logger.info(f"[?] Starting Dynamic Analysis on {len(unique_fields)} unique fields...\n")

        for f in unique_fields:
            if f.behavior == FieldBehavior.CALCULATED:
                continue

            self.logger.info(f"[MUTATION] Field: {f}")

            f.valid_values: list[str] = []
            for mutation_hex_tuple in self.get_random_combinations(f.size, sample_size=1000):
                mutation_hex: str = "".join(f"{b:02x}" for b in mutation_hex_tuple)

                self.logger.debug(f"    [*] Field: {f.name}, testing mutation value: {mutation_hex}, original: {seed[f.relative_pos * 2 : (f.relative_pos + f.size) * 2]}")
                response = b"0"
                try:
                    mutated_hex: str = self._inject_mutation(f, seed, mutation_hex, unique_fields=unique_fields).hex()
                    self._validator.validate(mutated_hex, is_request=True)
                    self._sock.sendall(bytes.fromhex(mutated_hex))
                    response: bytes = self._sock.recv(1024)
                    self._responses.append(response.hex())

                    if len(response) > 0 and response.hex()[:2] != "0000":
                        self.logger.debug(f"    [OK] Field: {f.name}, Mutation Accepted: {mutation_hex}, Response: {response.hex()}")
                        f.valid_values.append(mutation_hex)

                except Exception as e:
                    self.logger.trace(f"    [ERROR] Exception during mutation testing: {e}")
                    if f.invalid_values.get(str(e)) is None:
                        f.invalid_values[str(e)] = []
                    f.invalid_values[str(e)].append(mutation_hex)
                    # f.set_behavior(FieldBehavior.SERVER_ERROR)

                    self._sock.close()
                    self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self._sock.settimeout(1)
                    self.logger.info(f"Connecting to {self._protocol_info.protocol_name} server at localhost:{self._protocol_info.custom_port}")
                    self._sock.connect(("localhost", self._protocol_info.custom_port))

                if len(f.valid_values) > 50:
                    f.set_behavior(FieldBehavior.FUZZABLE)
                    f.accepted = True
                    break
                if f.get_biggest_invalid_category_size() > 10 and len(f.valid_values) == 0:
                    self.logger.info(f"    [!] Field {f.name} has a large invalid category, marking as CONSTRAINED.")
                    f.set_behavior(FieldBehavior.CONSTRAINED)
                    break
                if len(f.valid_values) > 0:
                    self.logger.info(f"    [*] Field {f.name} valid values count: {len(f.valid_values)}, largest invalid category size: {f.get_biggest_invalid_category_size()}")
                    f.set_behavior(FieldBehavior.FUZZABLE)
                    break

        self.analyze2(unique_fields, seed)

    def analyze2(self, unique_fields: list[RawField], seed: str) -> None:
        for f in unique_fields:
            for _ in range(100):
                if f.name == "modbus.func_code":
                    new_hex = "ff"
                    mutated_hex = self._inject_mutation(f, seed, new_hex, unique_fields=unique_fields).hex()
                    self._sock.sendall(bytes.fromhex(mutated_hex))
                    response = self._sock.recv(1024)
                    print(f"Testing func_code mutation: {mutated_hex}, Response: {response.hex()}")
                    self._responses.append(response.hex())

    def _create_mutation(self, target_field: RawField, base_payload_bytes: bytes) -> tuple[bytearray, str]:
        """Create a copy of the payload with the target field slightly mutated."""
        payload_copy = bytearray(base_payload_bytes)

        start_index = target_field.relative_pos
        end_index = start_index + target_field.size

        random_bytes = bytearray(random.getrandbits(8) for _ in range(target_field.size))

        payload_copy[start_index:end_index] = random_bytes

        mutated_field_hex = random_bytes.hex()

        return payload_copy, mutated_field_hex

    def _inject_mutation(self, target_field: RawField, base_payload_bytes: str, mutation_hex: str, unique_fields: list[RawField]) -> bytearray:
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
                crc_value = dnp3_crc_simple(payload_copy[prev:start_crc])
                prev = end_crc
                self.logger.trace(f"New crc start: {start_crc} end: {end_crc} value: {crc_value:#04x}")
                payload_copy = payload_copy[:start_crc] + crc_value.to_bytes(crc.size, byteorder="little") + payload_copy[end_crc:]

        return payload_copy


def dnp3_crc_simple(data_part: bytearray) -> int:
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
