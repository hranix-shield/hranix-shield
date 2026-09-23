"""Hranix Shield — server package.

`__version__` is read by the diagnostics bundle (A-14,
`app.services.diagnostics.environment_info`) so a downloaded report is
self-identifying without needing the git history it was generated from.
Bump manually per release; Phase 0 has no packaging/release pipeline yet
to automate this.
"""

__version__ = "0.1.3"
