"""Module: packet_struct.py."""

from rich.console import Console
from rich.table import Table

from proteus.model.raw_field import RawField


class PacketStruct:
    """Class representing the structure of a dissected packet, including its raw fields and methods for analyzing and visualizing the fuzzing plan based on field behaviors."""

    def print_plan(self, fuzzing_plan: list[RawField]) -> None:
        """Print the fuzzing plan in a tabular format using the Rich library.

        Displaying the behavior, field name, position, length, default value, valid values, invalid values,
        and whether the field was accepted during validation.
        """
        table = Table(title="Final Fuzzing Plan", show_header=True, header_style="bold magenta")
        table.add_column("BEHAVIOR")
        table.add_column("FIELD NAME")
        table.add_column("POS", justify="right")
        table.add_column("LEN", justify="right")
        table.add_column("DEFAULT", justify="left", max_width=10)
        table.add_column("VALID", overflow="fold")
        table.add_column("INVALID", overflow="fold")
        table.add_column("ACCEPTED", justify="center")

        for item in fuzzing_plan:
            behavior_markup = f"[{item.behavior.color}]{item.behavior.value}[/{item.behavior.color}]"
            table.add_row(
                behavior_markup, item.name, str(item.relative_pos), str(item.size), str(item.val), str(item.valid_values[:5]), str(item.invalid_values), str(item.accepted)
            )
        Console().print(table)
