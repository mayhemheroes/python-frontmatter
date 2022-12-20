#! /usr/bin/env python3
from json import JSONDecodeError

import atheris
import sys

from yaml.error import YAMLError

import fuzz_helpers

with atheris.instrument_imports(include=["frontmatter"]):
    import frontmatter

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        if fdp.ConsumeBool():
            post = frontmatter.loads(fdp.ConsumeRemainingString())
            frontmatter.dumps(post)
        else:
            frontmatter.parse(fdp.ConsumeRemainingString())
    except (YAMLError, JSONDecodeError) as e:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
