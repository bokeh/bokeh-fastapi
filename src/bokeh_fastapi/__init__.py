try:
    from ._version import __version__
except ModuleNotFoundError:
    import warnings

    warnings.warn("bokeh_fastapi was not properly installed!")
    del warnings

    __version__ = "UNKNOWN"

from .application import BokehFastAPI
