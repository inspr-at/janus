#!/usr/bin/env python3
"""Executable migration, signed release and rollback contract fixtures."""
import copy
import datetime
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from calendar_version import *


def module(file):
    spec=importlib.util.spec_from_file_location(file.replace('-','_'),ROOT/'scripts'/file)
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def shifted(value, seconds):
    return (calendar(value)+datetime.timedelta(seconds=seconds)).strftime('%y%m%d%H%M%S')+'.0.0'


class CalendarMigration(unittest.TestCase):
    def test_strict_dates_and_grammar(self):
        for value in ['260922094507.0.0','280229235959.0.0','991231235959.0.0']: calendar(value)
        for value in ['0.1.44','26.09.22','20260922094507.0.0','090922120000.0.0','260229120000.0.0','260431120000.0.0','260922240000.0.0','260922126000.0.0','260922125960.0.0','260922094507.0.1','260922094507.0.0-rc1','260922094507.0.0+sha']:
            with self.subTest(value=value),self.assertRaises(ValueError): calendar(value)

    def test_reservation_collision(self):
        value=source()['version']; meta=metadata_for_tag('go-envelope-v'+value)
        before=shifted(value,-1); after=shifted(value,1)
        with self.assertRaises(ValueError): reserve(value,[meta])
        with self.assertRaises(ValueError): reserve(before,[meta])
        self.assertEqual(reserve(after,[meta]),after)
        with self.assertRaises(ValueError): reserve(after,[{**meta,'version_scheme':'unknown'}])

    def test_declared_scheme_anchor_and_mixed_era_ordering(self):
        for name, channel in source()['channels'].items():
            tag=channel['tag_prefix']+source()['version']; meta=metadata_for_tag(tag)
            self.assertEqual(validate_release(tag,meta),meta)
            for scheme in [None,'legacy','inspr-calendar-v1','unknown','']:
                bad={**meta,'version_scheme':scheme}
                with self.assertRaises(ValueError): validate_release(tag,bad)
            with self.assertRaises(ValueError): validate_release(tag,None)
            anchor=channel['migration']['first_calendar_version']
            wrong=2 if meta['version']==anchor else channel['migration']['first_calendar_release_sequence']
            with self.assertRaises(ValueError): validate_release(tag,{**meta,'release_sequence':wrong})
            later=shifted(anchor,1)
            with self.assertRaises(ValueError): validate_release(channel['tag_prefix']+later,{**meta,'version':later,'release_sequence':1})
            validate_release(channel['tag_prefix']+later,{**meta,'version':later,'release_sequence':2})
            legacy=validate_release(channel['tag_prefix']+channel['migration']['last_legacy_version'],None)
            self.assertGreater(compare(meta,legacy),0)
            self.assertLess(compare(legacy,meta),0)
            with self.assertRaises(ValueError): compare(meta,{**legacy,'release_sequence':999})
            with self.assertRaises(ValueError): compare(meta,{**legacy,'release_channel':'other'})

    def test_current_source_mirrors_and_tag_pins(self):
        module('check-calendar-release.py').check_source()
        for tag in ['go-envelope-v1.185','rust-engine-v0.1.44','go-envelope-v260922094507.0.1']:
            with self.assertRaises(ValueError): metadata_for_tag(tag)

    def test_signed_manifest_and_exact_rollback(self):
        checker=module('check-source-release.py'); release=module('check-calendar-release.py')
        policy=json.loads(checker.POLICY.read_text()); checker.validate_policy(policy)
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'source.json'; bundle=pathlib.Path(directory)/'bundle.json';bundle.write_text('{}')
            for name, channel in source()['channels'].items():
                image='ghcr.io/inspr-at/janus/'+('janus-engine' if name=='stable' else 'janus-envelope')
                tag=channel['tag_prefix']+source()['version'];digest='sha256:'+'a'*64
                subprocess.run(['python3',str(ROOT/'scripts/create-source-release-manifest.py'),'--repository','inspr-at/janus','--tag',tag,'--commit','b'*40,'--workflow','.github/workflows/'+('rust.yml' if name=='stable' else 'go-envelope.yml'),'--image',image,'--image-digest',digest,'--output',str(output)],check=True)
                manifest=json.loads(output.read_text());checker.validate_manifest(policy,manifest,bundle,False)
                self.assertEqual(release.rollback(manifest,image,digest),image+'@'+digest)
                for key,value in [('version_scheme','legacy'),('version','260922094508.0.0'),('release_sequence',True),('release_channel','other')]:
                    bad={**manifest,key:value}
                    with self.assertRaises(checker.SourcePolicyError): checker.validate_manifest(policy,bad,bundle,False)
                with self.assertRaises(ValueError): release.rollback(manifest,image,'sha256:'+'c'*64)
                old={k:v for k,v in manifest.items() if k not in FIELDS};old['tag']=channel['tag_prefix']+channel['migration']['last_legacy_version']
                checker.validate_manifest(policy,old,bundle,False)
                self.assertEqual(release.rollback(old,image,digest),image+'@'+digest)

if __name__=='__main__': unittest.main()
