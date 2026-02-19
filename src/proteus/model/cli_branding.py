"""ClI branding and logging for the Proteus project."""

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()


class CliBranding:
    """Handles CLI branding and logging for the Proteus project."""

    HEADER = """
    ██████╗ ██████╗  ██████╗ ████████╗███████╗██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║   ██║██╔════╝
    ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║   ██║███████╗
    ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║   ██║╚════██║
    ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╔╝███████║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝ ╚══════╝
    """

    @staticmethod
    def show_intro() -> None:
        """Display the Proteus project branding and a quote in the CLI."""
        with Path("./paper/resources/metadata.json").open() as f:
            data = json.load(f)

            console.print(f"[bold purple]{CliBranding.HEADER}[/bold purple]")
            console.print(
                Panel.fit(
                    f"{data['name']}:{data['title']}",
                    title="[bold white]PROJECT PROTEUS for ICS Protocols[/bold white]",
                    border_style="red",
                )
            )

    @staticmethod
    def log_pivot(offset: int, original: bytearray, mutated: bytearray) -> None:
        """Log a successful pivot in the CLI."""
        console.print(f"[bold green]✓[/bold green] [bold white]Discrimen[/bold white] found at offset [yellow]{offset}[/yellow]: {original.hex()} -> {mutated.hex()}")
