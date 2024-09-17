import contextlib
import json
import sys
import unittest.mock
from pathlib import Path

import bokeh
import pytest
from bokeh.server.tornado import BokehTornado
from bokeh_fastapi import BokehFastAPI


def cache_path() -> Path:
    folder = Path(__file__).parents[3] / ".bokeh_fastapi_cache"
    folder.mkdir(parents=True, exist_ok=True)
    name = f"python-{sys.version_info[0]}.{sys.version_info[1]}-bokeh-{bokeh.__version__}.json"
    return folder / name


TESTS = []
PATCHES = {}


def update_required_patches(modules):
    global PATCHES
    for module in modules:
        if module in PATCHES:
            continue

        for name, obj in module.__dict__.items():
            if isinstance(obj, type) and issubclass(obj, BokehTornado):
                PATCHES[module.__name__] = name
                break


class BokehFastAPICompat(BokehFastAPI):
    pass
    # def __init__(self, *args, **kwargs):
    #     kwargs["websocket_origins"] = kwargs.pop("extra_websocket_origins")
    #     kwargs.pop("absolute_url", None)
    #     kwargs.pop("index", None)
    #     kwargs.pop("websocket_max_message_size_bytes", None)
    #     kwargs.pop("extra_patterns", None)
    #     super().__init__(*args, **kwargs)
    #
    # def initialize(self, *args, **kwargs):
    #     pass
    #
    # def start(self, *args, **kwargs):
    #     pass
    #
    # def __call__(self, *args, **kwargs):
    #     pass


@pytest.hookimpl(wrapper=True)
def pytest_collection_modifyitems(config, items):
    path = cache_path()
    if path.exists():
        with open(cache_path()) as file:
            cache = json.load(file)

        tests = set(cache["tests"])
        select = []
        deselect = []
        for item in items:
            (select if item.nodeid in tests else deselect).append(item)
        items[:] = select
        config.hook.pytest_deselected(items=deselect)

        for module_name, obj_name in cache["patches"].items():
            unittest.mock.patch(
                f"{module_name}.{obj_name}", new=BokehFastAPICompat
            ).start()
    else:
        update_required_patches({item.module for item in items})

    return (yield)


def pytest_terminal_summary():
    path = cache_path()
    if not path.exists():
        with open(path, "w") as file:
            json.dump({"patches": PATCHES, "tests": TESTS}, file, indent=2)


@pytest.fixture(autouse=True)
def detect_bokeh_tornado_usage(request):
    update_required_patches(
        [
            module
            for name, module in sys.modules.items()
            if (name == "bokeh" or name.startswith("bokeh."))
            and name != "bokeh.server.tornado"
        ]
    )

    with contextlib.ExitStack() as stack:
        spies = [
            stack.enter_context(
                unittest.mock.patch(f"{module_name}.{obj_name}", wraps=BokehTornado)
            )
            for module_name, obj_name in PATCHES.items()
        ]

        yield

    global TESTS
    if any(spy.called for spy in spies):
        TESTS.append(request.node.nodeid)
