"""Domain errors translated into HTTP responses by the routing layer."""


class StegoError(Exception):
    """Base class for expected application errors."""


class InvalidMediaError(StegoError):
    """The uploaded object is not valid for the selected media engine."""


class CapacityError(StegoError):
    """The signed packet cannot fit in the selected carrier."""


class WrongStartLocationError(StegoError):
    """No valid frame exists at the location derived from the secret."""


class FeatureUnavailableError(StegoError):
    """The requested engine exists as a boundary but is not implemented yet."""
