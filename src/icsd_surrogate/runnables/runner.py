import argparse
import json
import logging
import secrets
import socket
import struct
from dataclasses import asdict
from pathlib import Path
from typing import cast

from logger_captain.logger import CustomLogger
from protocol_server.starter import Starter
from protocol_validator.protocol_info import ProtocolInfo
from protocol_validator.validator_base import ValidatorBase

from icsd_surrogate.analyzers.dynamic_field_analyzer import DynamicFieldAnalyzer
from icsd_surrogate.analyzers.protocol_explorer import ProtocolExplorer
from icsd_surrogate.model.raw_field import EnhancedJSONEncoder, FieldBehavior, RawField
from icsd_surrogate.results.packet_struct import PacketStruct


class ProtocolFuzzer:
    def __init__(self, protocol: str) -> None:
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.logger.debug(f"[+] Initializing Protocol Fuzzer for protocol: {protocol}")

        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self._validator = ValidatorBase(protocol)

        self._packet_struct_viewer = PacketStruct()

    def load_requests(self, pcap_path: str, packet: str) -> list[str]:
        if pcap_path:
            requests: list[str] = []
            with Path(pcap_path).open(encoding="utf-8") as f:
                requests.extend([line.split(",")[0].strip() for line in f])
            self.logger.info(f"[+] Loaded {len(requests)} requests from CSV file: {pcap_path}")
            return requests

        return [packet.replace(" ", "")]

    def analyze_and_fuzz(self, packet: str) -> None:
        self.logger.info(f"[+] Analyzing seed packet: {packet}")

        explorer = ProtocolExplorer(packet, self._protocol_info.name)
        explorer.dissect()
        analyzer = DynamicFieldAnalyzer(self._protocol_info.name)
        analyzer.analyze(packet, explorer.raw_fields)

        analyzer.cluster_responses_plotly(packet)

        self._packet_struct_viewer.print_plan(explorer.raw_fields)

        with Path(f"outputs/{self._protocol_info.name}_raw_fields.json").open("w") as f:
            json.dump([asdict(u) for u in explorer.raw_fields], f, indent=4, cls=EnhancedJSONEncoder)

        self.logger.info(f"[+] Saved raw fields to outputs/{self._protocol_info.name}_raw_fields.json")

    def construct_prefix(self, fields: list[RawField], stop_at_name: str) -> bytes:
        prefix = b""
        for field in fields:
            if field.name == stop_at_name:
                break

            field_bytes: bytes = bytes.fromhex(field.val)
            prefix += field_bytes

        return prefix

    def find_structural_variants(self, fields_json: list[RawField]) -> list[str]:
        pivot_field: RawField | None = None
        for field in fields_json:
            if "modbus.func_code" in field.name:
                pivot_field: RawField = field
                print(f"Selected Structural Pivot: {pivot_field.name}")
                break
        if not pivot_field:
            raise ValueError("No suitable pivot field found for structural analysis.")

        new_seeds: list[str] = []

        # Identify Length fields (CONSTRAINED fields before the pivot)
        length_fields: list[RawField] = [f for f in fields_json if f.behavior == FieldBehavior.CONSTRAINED and f.relative_pos < pivot_field.relative_pos]

        for val in ["01", "02", "03", "04", "05", "06"]:
            # Start with the raw bytes up to the pivot
            # (You would need the original raw packet for this, or reconstruct from 'val' fields)
            base_packet = self.construct_prefix(fields_json, stop_at_name=pivot_field.name)

            # Append the new pivot value
            base_packet += bytes.fromhex(val)
            print(f"Base Packet with new pivot {val}: {base_packet.hex()}")

            # STRATEGY: Probing for Structure
            # We don't know if this new type needs 0 bytes, 2 bytes, or 100 bytes following it.
            # We generate a gradient of lengths.

            for payload_len in [0, 2, 4, 8, 16]:
                payload = b"\x00" * payload_len
                candidate_pkt = base_packet + payload

                # 3. Fixup Lengths (The "Oracle")
                # If we identified a length field earlier, update it to match current size
                for len_field in length_fields:
                    candidate_pkt = self.fix_length_field(candidate_pkt, len_field)
                    try:
                        self.validate_seed("localhost", 5020, candidate_pkt)
                        new_seeds.append(candidate_pkt.hex())
                    except Exception as e:
                        self.logger.trace(f"Validation failed for candidate packet: {candidate_pkt.hex()} - Error: {e}")

        self.find_structural_variants2(new_seeds, pivot_field)
        return new_seeds

    def find_structural_variants2(self, new_seeds: list[str], pivot_field: RawField) -> None:
        for seed in new_seeds:
            explorer = ProtocolExplorer(seed, self._protocol_info.name)
            try:
                explorer.dissect()

                analyzer = DynamicFieldAnalyzer(self._protocol_info.name)
                analyzer.analyze(seed, explorer.raw_fields)

                self._packet_struct_viewer.print_plan(explorer.raw_fields)
                mutated_packet = seed
                for field in explorer.raw_fields:
                    if field.behavior == FieldBehavior.FUZZABLE and field.name != pivot_field.name:
                        self.logger.info(f"Mutating field {field.name} at pos {field.relative_pos} with size {field.size}")
                        mutated_val = secrets.token_hex(field.size)
                        mutated_packet = mutated_packet[: field.relative_pos * 2] + mutated_val + mutated_packet[(field.relative_pos + field.size) * 2 :]

                self.logger.info(f"Testing mutation for all fuzzable fields: {mutated_packet}")
            except Exception as e:
                self.logger.warning(f"Failed to dissect new seed {seed}: {e}")

    def validate_seed(self, target_ip: str, target_port: int, seed_bytes: bytes) -> dict:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)

        try:
            s.connect((target_ip, target_port))
            s.sendall(seed_bytes)
            response: bytes = s.recv(4096)

            if response.hex()[:4] == "0000":
                raise ValueError("Received response with all-zero header, likely invalid packet")
            if len(response) == 0:
                raise ValueError("Received empty response, likely invalid packet")
            if response.hex()[-2:] == "04":
                raise ValueError("Received response with only an error code, likely invalid packet")

            self.logger.debug(f"Sent: {seed_bytes.hex()} | Received: {response.hex() if response else 'No Response'}")

            self._validator.validate(seed_bytes.hex(), is_request=True)
        finally:
            s.close()

            # Heuristic: If we get data but no TransID match, it might be a generic error
        return {
            "status": "RESPONSE_RECEIVED",
            "valid": True,  # It's valid protocol, likely an application error
            "len": len(response),
            "data": response.hex(),
        }

    def fix_length_field(self, packet_bytes: bytes, len_field: RawField) -> bytes:
        length_value = len(packet_bytes) - 6
        # Pack the length as a big-endian unsigned 16-bit integer
        length_bytes = struct.pack(">H", length_value)
        # Replace the length field in the packet
        start_pos = len_field.relative_pos + 1
        end_pos = start_pos + len_field.size + 1
        return packet_bytes[:start_pos] + b"\x00" + length_bytes + packet_bytes[end_pos:]


def run(pcap_path: str, packet: str, protocol: str) -> None:
    fuzzer = ProtocolFuzzer(protocol)
    server_starter = Starter(protocol, 5020, delay=3)
    server_starter.start_server()
    requests: list[str] = fuzzer.load_requests(pcap_path, packet)
    for req in requests:
        fuzzer.analyze_and_fuzz(req)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Protocol Learner")
    parser.add_argument("--protocol", type=str, help="Protocol to use (e.g., mbtcp, s7comm, dnp3)")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level")

    group: argparse._MutuallyExclusiveGroup = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--seed", type=str, help="Hex string of the seed packet")
    group.add_argument("--pcap", type=str, help="Path to pcap file containing the seed packet")

    args: argparse.Namespace = parser.parse_args()

    CustomLogger.setup_logging("logs", "app.log", level=args.log_level)

    run(args.pcap, args.seed, args.protocol)
