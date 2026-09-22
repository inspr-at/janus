#!/usr/bin/env python3
"""Validate the source, Cargo mirror, release tag and exact-artifact rollback."""
import argparse
import json
import pathlib
import re
import sys
from calendar_version import SOURCE, ROOT, SCHEME, source, metadata_for_tag, validate_release


def check_source():
    data = source()
    cargo = (ROOT/'Cargo.toml').read_text().split('[workspace.package]',1)[1].split('\n[',1)[0]
    if re.search(r'^version = "([^"]+)"',cargo,re.M).group(1) != data['version']:
        raise ValueError('Cargo version differs from authoritative release source')
    for block in (ROOT/'Cargo.lock').read_text().split('[[package]]')[1:]:
        name = re.search(r'\nname = "([^"]+)"',block).group(1)
        if name.startswith('janus') and re.search(r'\nversion = "([^"]+)"',block).group(1) != data['version']:
            raise ValueError('workspace lock version mismatch')
    return data


def rollback(manifest, image, digest):
    if image != manifest.get('image') or digest != manifest.get('image_digest') or not re.fullmatch(r'sha256:[0-9a-f]{64}',digest):
        raise ValueError('rollback must use the signed exact image digest')
    metadata = {k:manifest[k] for k in ('version_scheme','version','release_channel','release_sequence') if k in manifest}
    validate_release(manifest['tag'], metadata or None)
    return image + '@' + digest


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--tag')
    parser.add_argument('--manifest',type=pathlib.Path)
    args=parser.parse_args()
    try:
        check_source()
        if args.tag: metadata_for_tag(args.tag)
        if args.manifest:
            manifest=json.loads(args.manifest.read_text())
            from calendar_version import FIELDS
            validate_release(manifest['tag'],{k:manifest[k] for k in FIELDS if k in manifest} or None)
        print('ok: calendar source, explicit scheme and version bindings')
    except (ValueError,KeyError,TypeError,OSError) as error:
        print(str(error),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
