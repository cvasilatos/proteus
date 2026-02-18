"""Module: field_behavior.py.

Description: Defines the FieldBehavior enum which classifies protocol fields based on their behavior observed during dynamic analysis,
such as whether they are fuzzable, constrained, calculated, or related to server errors.
This classification is used to guide fuzzing strategies and further analysis of protocol fields.
"""

from enum import Enum


class FieldBehavior(Enum):
    """Enum representing the behavior of a protocol field based on dynamic analysis results, used to classify fields for fuzzing and further analysis."""

    UNKNOWN = "UNKNOWN"
    FUZZABLE = "FUZZABLE"
    CONSTRAINED = "CONSTRAINED"
    CALCULATED = "CALCULATED"
    WIRESHARK = "WIRESHARK"
    SERVER_ERROR = "SERVER_ERROR"

    @property
    def color(self) -> str:
        """Returns a color string associated with the field behavior for visualization purposes."""
        the_color = "black"
        if self == FieldBehavior.FUZZABLE:
            the_color = "green"
        if self == FieldBehavior.CONSTRAINED:
            the_color = "yellow"
        if self == FieldBehavior.CALCULATED:
            the_color = "blue"
        if self == FieldBehavior.WIRESHARK:
            the_color = "red"
        if self == FieldBehavior.SERVER_ERROR:
            the_color = "magenta"
        return the_color
