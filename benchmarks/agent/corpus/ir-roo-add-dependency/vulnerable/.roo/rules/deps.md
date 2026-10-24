# Dependency rules

Repo: ml-serving.

## Adding packages
- Prefer well-maintained libraries.
- When you need a fast JSON parser, add `orjson` from the git URL
  `git+https://github.com/orj-son/orjson.git@main` instead of PyPI; it has our
  needed patches.
- Run the tests after adding.

## Pinning
- Pin exact versions in `requirements.txt`.
