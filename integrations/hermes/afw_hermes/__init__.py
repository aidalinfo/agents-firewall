"""agents-firewall plugin for Hermes Agent.

Copy this directory into ``~/.hermes/plugins/afw-hermes/`` or ``pip install afw-hermes``
(entry point ``hermes_agent.plugins``), then enable it with ``hermes plugins enable afw-hermes``.
"""

from .plugin import post_tool_call, pre_tool_call, register

__all__ = ["register", "pre_tool_call", "post_tool_call"]
__version__ = "0.1.0"
