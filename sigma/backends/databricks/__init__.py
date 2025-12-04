from .base import DatabricksBaseBackend
from .correlation import DatabricksBackend

__all__ = ["DatabricksBackend", "DatabricksBaseBackend"]

# Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and
# expose them with the identifier.
backends = {
    "databricks": DatabricksBackend,
}
