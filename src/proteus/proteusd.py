"""ProteusD: A Protocol Fuzzer for ICS Protocols."""

import json
import logging
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import cast

import click
from cursusd.starter import Starter
from decimalog.logger import CustomLogger
from praetor.praetord import ValidatorBase
from praetor.protocol_info import ProtocolInfo

from proteus.analyzers.dynamic_field_analyzer import DynamicFieldAnalyzer
from proteus.analyzers.protocol_explorer import ProtocolExplorer
from proteus.model.cli_branding import CliBranding
from proteus.model.raw_field import EnhancedJSONEncoder, FieldBehavior, RawField
from proteus.results.packet_struct import PacketStruct
from proteus.utils.constants import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    MODBUS_FUNCTION_CODE_FIELD,
    STRUCTURAL_VARIANT_FUNCTION_CODES,
    STRUCTURAL_VARIANT_PAYLOAD_LENGTHS,
    VALIDATION_TIMEOUT,
)
from proteus.utils.packet_manipulator import PacketManipulator
from proteus.utils.response_validator import is_valid_response
from proteus.utils.socket_manager import SocketManager


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

    def _find_structural_variants(self, fields_json: list[RawField]) -> list[str]:
        """Find structural variants by testing different function codes and payload lengths.
        
        Args:
            fields_json: List of raw fields from the seed packet
            
        Returns:
            List of new seed packet hex strings
            
        Raises:
            ValueError: If no suitable pivot field is found
        """
        pivot_field = self._find_pivot_field(fields_json)
        length_fields = self._identify_length_fields(fields_json, pivot_field)
        new_seeds = self._generate_variant_candidates(fields_json, pivot_field, length_fields)
        
        # Process new seeds for further analysis (side effects: prints and logs results)
        self._find_structural_variants2(new_seeds, pivot_field)
        return new_seeds

    def _find_pivot_field(self, fields: list[RawField]) -> RawField:
        """Identify the pivot field for structural analysis.
        
        Args:
            fields: List of raw fields
            
        Returns:
            The pivot field
            
        Raises:
            ValueError: If no suitable pivot field is found
        """
        for field in fields:
            if MODBUS_FUNCTION_CODE_FIELD in field.name:
                print(f"Selected Structural Pivot: {field.name}")
                return field
        raise ValueError("No suitable pivot field found for structural analysis.")

    def _identify_length_fields(self, fields: list[RawField], pivot_field: RawField) -> list[RawField]:
        """Identify length fields that appear before the pivot field.
        
        Args:
            fields: List of raw fields
            pivot_field: The pivot field for analysis
            
        Returns:
            List of length fields
        """
        return [
            f for f in fields
            if f.behavior == FieldBehavior.CONSTRAINED and f.relative_pos < pivot_field.relative_pos
        ]

    def _generate_variant_candidates(
        self,
        fields: list[RawField],
        pivot_field: RawField,
        length_fields: list[RawField],
    ) -> list[str]:
        """Generate candidate packets with different pivot values and payload lengths.
        
        Args:
            fields: List of raw fields
            pivot_field: The pivot field to mutate
            length_fields: List of length fields to update
            
        Returns:
            List of valid candidate packet hex strings
        """
        new_seeds: list[str] = []

        for val in STRUCTURAL_VARIANT_FUNCTION_CODES:
            base_packet = PacketManipulator.construct_prefix(fields, stop_at_name=pivot_field.name)
            base_packet += bytes.fromhex(val)
            print(f"Base Packet with new pivot {val}: {base_packet.hex()}")

            for payload_len in STRUCTURAL_VARIANT_PAYLOAD_LENGTHS:
                payload = b"\x00" * payload_len
                candidate_pkt = base_packet + payload

                # Fix length fields to match current packet size
                for len_field in length_fields:
                    candidate_pkt = PacketManipulator.fix_length_field(candidate_pkt, len_field)
                
                # Validate after all length fields have been fixed
                try:
                    self._validate_seed(DEFAULT_HOST, DEFAULT_PORT, candidate_pkt)
                    new_seeds.append(candidate_pkt.hex())
                except Exception as e:
                    self.logger.trace(f"Validation failed for candidate packet: {candidate_pkt.hex()} - Error: {e}")

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
        """Validate a seed packet by sending it to the server and checking the response.
        
        Args:
            target_ip: Target server IP address
            target_port: Target server port
            seed_bytes: Seed packet bytes to validate
            
        Returns:
            Validation result dictionary
            
        Raises:
            ValueError: If the response is invalid
        """
        with SocketManager(target_ip, target_port, timeout=VALIDATION_TIMEOUT) as sock_mgr:
            sock_mgr.send(seed_bytes)
            response: bytes = sock_mgr.receive()

            if not is_valid_response(response):
                raise ValueError("Received invalid response")

            self.logger.debug(f"Sent: {seed_bytes.hex()} | Received: {response.hex()}")
            self._validator.validate(seed_bytes.hex(), is_request=True)

        return {
            "status": "RESPONSE_RECEIVED",
            "valid": True,
            "len": len(response),
            "data": response.hex(),
        }


@click.command()
@click.option("--protocol", required=True, help="Protocol to use (e.g., mbtcp, s7comm, dnp3)")
@click.option("--log-level", default="INFO", show_default=True, help="Logging level")
@click.option("--seed", required=False, help="Hex string of the seed packet")
@click.option("--pcap", required=False, help="Path to pcap file containing the seed packet")
def run(protocol: str, log_level: str, seed: str | None, pcap: str | None) -> None:
    """Run the Protocol Fuzzer with the specified parameters, including loading seed packets, analyzing them, and applying fuzzing strategies."""
    if bool(seed) == bool(pcap):
        raise click.UsageError("Provide exactly one of --seed or --pcap.")

    CustomLogger.setup_logging("logs", "app", level=log_level)

    cli_branding = CliBranding()
    cli_branding.show_intro()

    fuzzer = ProtocolFuzzer(protocol)
    server_starter = Starter(protocol, DEFAULT_PORT, delay=3)
    server_starter.start_server()
    requests: list[str] = fuzzer.load_requests(pcap or "", seed or "")
    for req in requests:
        fuzzer.analyze_and_fuzz(req)


if __name__ == "__main__":
    run()
