"""Module: raw_field.py."""

import json
from dataclasses import dataclass, field
from enum import Enum

from proteus.model.field_behavior import FieldBehavior


class EnhancedJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle serialization of FieldBehavior enum values when saving RawField instances to JSON format.

    This allows for easy storage and retrieval of RawField data, including the behavior classification, in a human-readable format for further analysis and visualization.
    """

    def default(self, o: FieldBehavior) -> str:
        """Override the default method to serialize FieldBehavior enum values as their string representation when encoding to JSON."""
        if isinstance(o, Enum):
            return o.value
        return super().default(o)


@dataclass
class RawField:
    """Data class representing a raw field extracted from a dissected packet.

    Including its name, position, size, value, layer, and behavior classification based on dynamic analysis results.
    This class is used to store and manage information about protocol fields for further analysis and fuzzing.
    """

    name: str = field(default="")
    wireshark_name: str = field(default="")
    display_name: str = field(default="")
    pos: int = field(default=0)
    relative_pos: int = field(default=0)
    size: int = field(default=0)
    val: str = field(default="")
    valid_values: list[str] = field(default_factory=list, init=True)
    invalid_values: dict[str, list[str]] = field(default_factory=dict, init=True)
    layer: str = field(default="")
    behavior: FieldBehavior = field(default=FieldBehavior.UNKNOWN)
    accepted: bool = field(default=False)

    def set_behavior(self, behavior: FieldBehavior) -> None:
        """Set the behavior of the field, but only if it is currently UNKNOWN.

        This ensures that once a field's behavior is classified based on dynamic analysis results,
        it cannot be overwritten by subsequent analyses, preserving the most specific classification for fuzzing and further analysis purposes.
        """
        if self.behavior == FieldBehavior.UNKNOWN:
            self.behavior = behavior

    def get_biggest_invalid_category_size(self) -> int:
        """Return the size of the largest category of invalid values for this field, which can be used to determine the maximum size of mutations to apply during fuzzing.

        This helps ensure that mutations are appropriately sized to trigger potential vulnerabilities without exceeding
        the bounds of what has been observed as invalid during dynamic analysis.
        """
        max_size = 0
        for values in self.invalid_values.values():
            max_size = max(max_size, len(values))
        return max_size

    def __str__(self) -> str:
        """Return a string representation of the RawField, including its name, Wireshark name, layer, display name, position, size, behavior, and whether was accepted validation.

        The string is formatted with color codes for better visualization when printed in the console.
        """
        c_green = "\033[32m"
        c_yellow = "\033[33m"
        c_blue = "\033[34m"
        c_magenta = "\033[35m"
        c_cyan = "\033[36m"
        c_red = "\033[31m"
        c_white = "\033[37m"
        reset = "\033[0m"

        return (
            f"  {c_green}RawField: {self.name}, "
            f"  {c_yellow}W_Name: {self.wireshark_name}, "
            f"  {c_blue}Layer: {self.layer}, "
            f"  {c_magenta}D_Name: {self.display_name}, "
            f"  {c_cyan}Pos: {self.pos} (+{self.relative_pos}), "
            f"  {c_red}Size: {self.size}, "
            f"  {c_white}Behavior: {self.behavior.value}, "
            f"  {c_green}Accepted: {self.accepted}{reset}"
        )
