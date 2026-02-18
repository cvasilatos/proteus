"""ProteusD: A Protocol Fuzzer for ICS Protocols."""

import argparse
import json
import logging
import secrets
import socket
import struct
from dataclasses import asdict
from pathlib import Path
from typing import cast

from cursusd.starter import Starter
from decimalog.logger import CustomLogger
from praetor.praetord import ValidatorBase
from praetor.protocol_info import ProtocolInfo

from proteus.analyzers.dynamic_field_analyzer import DynamicFieldAnalyzer
from proteus.analyzers.protocol_explorer import ProtocolExplorer
from proteus.model.raw_field import EnhancedJSONEncoder, FieldBehavior, RawField
from proteus.results.packet_struct import PacketStruct


class ProtocolFuzzer:
    """Main class for the Protocol Fuzzer.

    Responsible for loading seed packets, analyzing them to extract protocol fields, and applying fuzzing strategies based on the analysis
    results. It manages the overall workflow of the fuzzing process, including validation of seeds, dissection of packets, and generation
    of new test cases based on identified field behaviors and structural variants.
    """

    def __init__(self, protocol: str) -> None:
        """Initialize the ProtocolFuzzer with the specified protocol, setting up logging, protocol information, and a packet structure viewer for visualizing the analysis results.

        This sets the stage for loading seed packets and performing analysis and fuzzing based on the protocol's characteristics.
        """
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.logger.debug(f"[+] Initializing Protocol Fuzzer for protocol: {protocol}")

        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self._validator = ValidatorBase(protocol)

        self._packet_struct_viewer = PacketStruct()

    def load_requests(self, pcap_path: str, packet: str) -> list[str]:
        """Load seed packets from a specified pcap file or use a provided hex string as the seed packet.

        This method checks if a pcap path is provided, and if so, it reads the requests from the file. If not,
        it uses the provided hex string as the single seed packet for analysis and fuzzing.
        """
        if pcap_path:
            requests: list[str] = []
            with Path(pcap_path).open(encoding="utf-8") as f:
                requests.extend([line.split(",")[0].strip() for line in f])
            self.logger.info(f"[+] Loaded {len(requests)} requests from CSV file: {pcap_path}")
            return requests

        return [packet.replace(" ", "")]

    def analyze_and_fuzz(self, packet: str) -> None:
        """Analyze the provided seed packet to extract protocol fields and their behaviors, then apply fuzzing strategies based on the analysis results.

        This includes dissecting the packet, classifying fields, generating new test cases based on structural variants,
        and validating the new test cases against the target server to identify potential vulnerabilities.
        """
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

    def _construct_prefix(self, fields: list[RawField], stop_at_name: str) -> bytes:
        prefix = b""
        for field in fields:
            if field.name == stop_at_name:
                break

            field_bytes: bytes = bytes.fromhex(field.val)
            prefix += field_bytes

        return prefix

    def _find_structural_variants(self, fields_json: list[RawField]) -> list[str]:
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
            base_packet: bytes = self._construct_prefix(fields_json, stop_at_name=pivot_field.name)

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
                    candidate_pkt = self._fix_length_field(candidate_pkt, len_field)
                    try:
                        self._validate_seed("localhost", 5020, candidate_pkt)
                        new_seeds.append(candidate_pkt.hex())
                    except Exception as e:
                        self.logger.trace(f"Validation failed for candidate packet: {candidate_pkt.hex()} - Error: {e}")

        self._find_structural_variants2(new_seeds, pivot_field)
        return new_seeds

    def _find_structural_variants2(self, new_seeds: list[str], pivot_field: RawField) -> None:
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

    def _validate_seed(self, target_ip: str, target_port: int, seed_bytes: bytes) -> dict:
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

    def _fix_length_field(self, packet_bytes: bytes, len_field: RawField) -> bytes:
        length_value = len(packet_bytes) - 6
        # Pack the length as a big-endian unsigned 16-bit integer
        length_bytes = struct.pack(">H", length_value)
        # Replace the length field in the packet
        start_pos = len_field.relative_pos + 1
        end_pos = start_pos + len_field.size + 1
        return packet_bytes[:start_pos] + b"\x00" + length_bytes + packet_bytes[end_pos:]


def run(pcap_path: str, packet: str, protocol: str) -> None:
    """Run the Protocol Fuzzer with the specified parameters, including loading seed packets, analyzing them, and applying fuzzing strategies."""
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

    CustomLogger.setup_logging("logs", "app", level=args.log_level)

    run(args.pcap, args.seed, args.protocol)
