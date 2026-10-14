"""Version-tolerant discovery of Slither's installed detector classes."""

import inspect
import logging

from slither.detectors.abstract_detector import AbstractDetector

logger = logging.getLogger(__name__)


def _discover_detectors():
    """Load detector classes exported by this Slither version."""
    from slither.detectors import all_detectors

    discovered = set()
    for _, detector_class in inspect.getmembers(all_detectors, inspect.isclass):
        if (
            detector_class is not AbstractDetector
            and issubclass(detector_class, AbstractDetector)
            and not inspect.isabstract(detector_class)
            and detector_class.__module__.startswith("slither.detectors.")
        ):
            discovered.add(detector_class)

    if not discovered:
        raise RuntimeError(
            "Slither's all_detectors module did not expose any concrete detector classes."
        )
    return sorted(discovered, key=lambda detector_class: detector_class.__name__)


DETECTORS = _discover_detectors()
