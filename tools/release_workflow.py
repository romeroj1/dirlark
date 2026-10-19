"""Workflow entrypoints; environment values become argument data, never shell code."""
import argparse
import os
from pathlib import Path
try:
    import release_package
    import release_draft
except ModuleNotFoundError:
    from tools import release_package, release_draft


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=('build', 'draft'))
    args = parser.parse_args()
    tag = os.environ['RELEASE_TAG']
    release_package.version(tag)
    if args.step == 'build':
        release_package.build(os.environ['RELEASE_PLATFORM'], tag, Path('release-out'))
    else:
        commit = os.environ['GITHUB_SHA']
        assets = release_draft.prepare(Path('release-downloads'), tag, commit, Path('release-assets'))
        release_draft.draft(tag, commit, assets)


if __name__ == '__main__':
    main()
