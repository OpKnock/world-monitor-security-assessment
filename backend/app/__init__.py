"""World Monitor Security Assessment Platform — application package.

Public surface
--------------
* :attr:`__version__` — semantic version shared with :mod:`backend.app.config`.
* :mod:`backend.app.main` — FastAPI application factory.
* :mod:`backend.app.config` — validated runtime settings.
* :mod:`backend.app.db` — SQLAlchemy engine / session helpers.
* :mod:`backend.app.models` — ORM models.
* :mod:`backend.app.security` — authentication primitives.

Keeping this module minimal avoids circular imports; heavy objects are
imported explicitly where needed.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
