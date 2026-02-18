from rich.console import Console
from rich.table import Table

from icsd_surrogate.model.raw_field import RawField


class PacketStruct:
    def print_plan(self, fuzzing_plan: list[RawField]) -> None:
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
