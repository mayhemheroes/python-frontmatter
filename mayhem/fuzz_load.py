#! /usr/bin/env python3
import atheris
import sys

import fuzz_helpers

# Instrument frontmatter AND its parsing backends. frontmatter is a thin wrapper: the real parsing
# logic (and therefore the interesting coverage/edges) lives in PyYAML / toml / json, which
# `import frontmatter` pulls in transitively at module load (frontmatter.default_handlers). A bare
# instrument_imports() (no include=) instruments every module imported inside this block, so those
# backends get coverage feedback too — `include=["frontmatter"]` would restrict instrumentation to
# the ~tens of edges of the wrapper and leave the parsers dark, so fuzzing discovers ~0 new edges.
#
# The error types MUST be imported INSIDE this block (not before it): importing `yaml` before
# instrument_imports() caches an UNinstrumented yaml, and Python's module cache makes the later
# instrumented import a no-op — so yaml would never get coverage.
with atheris.instrument_imports():
    import frontmatter
    from json import JSONDecodeError
    from yaml.error import YAMLError
    try:
        from toml import TomlDecodeError
    except Exception:  # toml backend optional
        TomlDecodeError = ()


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        if fdp.ConsumeBool():
            post = frontmatter.loads(fdp.ConsumeRemainingString())
            # The serialize round-trip exercises the encoder backends too, but it is auxiliary to the
            # parse target: toml/yaml encoders raise assorted errors (IndexError, TypeError, ...) on
            # the arbitrary dicts fuzzing produces — those are not parse defects, so don't let them
            # abort the run.
            try:
                frontmatter.dumps(post)
            except Exception:
                pass
        else:
            frontmatter.parse(fdp.ConsumeRemainingString())
    except (YAMLError, JSONDecodeError, TomlDecodeError, TypeError) as e:
        # Expected "this input is not valid front matter" signals from the parsing backends (YAML/
        # TOML/JSON errors) and from frontmatter itself (TypeError "keywords must be strings" when a
        # YAML mapping has non-string keys is passed to Post(**metadata)). Not crashes — swallow them
        # so the fuzzer keeps exploring the parser and corpus replay during Mayhem coverage
        # collection doesn't exit on a malformed seed (which would report 0 edges).
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
