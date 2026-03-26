# bokeh-fastapi

Compatibility layer between Bokeh and FastAPI.

## Installation

```shell
pip install bokeh-fastapi
```

## Usage

Check out the guide(s) below:

- [Panel FastAPI Integration](https://panel.holoviz.org/how_to/integrations/FastAPI.html) guide

## Building and publishing

```shell
git tag vMAJOR.MINOR.PATCH # e.g. v0.1.7
python -m build
twine upload dist/bokeh_fastapi*
git push --tags
```
