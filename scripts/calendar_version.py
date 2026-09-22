"""Explicit mixed-era coordinates; never infer a version scheme from a tag."""
import datetime
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'go-envelope/internal/versioninfo/release.json'
SCHEME = 'inspr-calendar-v2'
LEGACY_GO = r'go-envelope-v[1-9][0-9]*\.[0-9]+'
LEGACY_RUST = r'rust-engine-v[0-9]+\.[0-9]+\.[0-9]+'
GO_PATTERN = r'go-envelope-v([1-9][0-9]*\.[0-9]+|[1-9][0-9]{11}\.0\.0)'
RUST_PATTERN = r'rust-engine-v([0-9]+\.[0-9]+\.[0-9]+|[1-9][0-9]{11}\.0\.0)'
FIELDS = {'version_scheme', 'version', 'release_channel', 'release_sequence'}


def calendar(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{11}\.0\.0', value):
        raise ValueError('invalid calendar coordinate')
    stamp = datetime.datetime.strptime('20' + value[:12], '%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc)
    if stamp.strftime('%y%m%d%H%M%S') != value[:12]:
        raise ValueError('noncanonical calendar coordinate')
    return stamp


def source():
    data = json.loads(SOURCE.read_text())
    if data['schema'] != 'inspr.janus.release.v1' or data['version_scheme'] != SCHEME:
        raise ValueError('invalid release source')
    if calendar(data['version']).strftime('%Y-%m-%dT%H:%M:%SZ') != data['reserved_at']:
        raise ValueError('reservation does not match coordinate')
    for channel in data['channels'].values():
        if type(channel['release_sequence']) is not int or channel['release_sequence'] < 1:
            raise ValueError('invalid release sequence')
        anchor = channel['migration']
        if not re.fullmatch(r'[0-9a-f]{40}', anchor['last_legacy_commit']):
            raise ValueError('legacy anchor must be a full peeled commit')
        if anchor['legacy_scheme'] != 'legacy' or anchor['first_calendar_release_sequence'] != 1:
            raise ValueError('invalid migration anchor')
        calendar(anchor['first_calendar_version'])
        if (data['version'] == anchor['first_calendar_version']) != (channel['release_sequence'] == anchor['first_calendar_release_sequence']):
            raise ValueError('release sequence disagrees with migration anchor')
        if calendar(data['version']) < calendar(anchor['first_calendar_version']):
            raise ValueError('coordinate predates migration')
    return data


def metadata_for_tag(tag):
    data = source()
    for name, channel in data['channels'].items():
        if tag == channel['tag_prefix'] + data['version']:
            return dict(version_scheme=data['version_scheme'], version=data['version'], release_channel=name, release_sequence=channel['release_sequence'])
    raise ValueError('tag does not match reserved release coordinate')


def validate_release(tag, metadata):
    """Absent metadata is accepted only by the bounded, immutable legacy channel."""
    data = source()
    matches = [(name, c) for name, c in data['channels'].items() if tag.startswith(c['tag_prefix'])]
    if len(matches) != 1:
        raise ValueError('unknown release channel')
    name, channel = matches[0]
    value = tag[len(channel['tag_prefix']):]
    if metadata is None:
        pattern = LEGACY_GO if name == 'envelope-stable' else LEGACY_RUST
        if not re.fullmatch(pattern, tag):
            raise ValueError('legacy tag invalid')
        if tuple(map(int, value.split('.'))) > tuple(map(int, channel['migration']['last_legacy_version'].split('.'))):
            raise ValueError('undeclared release beyond legacy anchor')
        return dict(version_scheme='legacy', version=value, release_channel=name, release_sequence=0)
    if set(metadata) != FIELDS or metadata['version_scheme'] != SCHEME or metadata['version'] != value or metadata['release_channel'] != name:
        raise ValueError('release metadata mismatch')
    calendar(value)
    if type(metadata['release_sequence']) is not int or metadata['release_sequence'] < channel['migration']['first_calendar_release_sequence']:
        raise ValueError('invalid release sequence')
    if (value == channel['migration']['first_calendar_version']) != (metadata['release_sequence'] == channel['migration']['first_calendar_release_sequence']):
        raise ValueError('migration sequence mismatch')
    if calendar(value) < calendar(channel['migration']['first_calendar_version']):
        raise ValueError('coordinate before migration')
    return metadata


def compare(left, right):
    if left['release_channel'] != right['release_channel']:
        raise ValueError('different release channels')
    for item in (left, right):
        if set(item) != FIELDS or (item.get('version_scheme') == 'legacy' and (type(item.get('release_sequence')) is not int or item['release_sequence'] != 0)):
            raise ValueError('invalid normalized legacy release')
        data = source()['channels'][item['release_channel']]
        validate_release(data['tag_prefix'] + item['version'], None if item['version_scheme'] == 'legacy' else item)
    if left['version_scheme'] != right['version_scheme']:
        return (left['release_sequence'] > right['release_sequence']) - (left['release_sequence'] < right['release_sequence'])
    a = calendar(left['version']) if left['version_scheme'] == SCHEME else tuple(map(int, left['version'].split('.')))
    b = calendar(right['version']) if right['version_scheme'] == SCHEME else tuple(map(int, right['version'].split('.')))
    return (a > b) - (a < b)


def reserve(value, published):
    calendar(value)
    for item in published:
        channel = source()['channels'].get(item.get('release_channel'))
        if channel is None or item.get('version_scheme') not in ('legacy',SCHEME):
            raise ValueError('unknown published release scheme or channel')
        validate_release(channel['tag_prefix']+item['version'],None if item['version_scheme']=='legacy' else item)
    if any(item['version_scheme'] == SCHEME and (calendar(item['version']) >= calendar(value)) for item in published):
        raise ValueError('same-second collision or nonmonotonic coordinate')
    return value
