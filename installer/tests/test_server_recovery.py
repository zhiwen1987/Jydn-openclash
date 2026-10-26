"""Linux-only fault tests: all Docker/systemd commands are replaced by stubs."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

if os.name=='nt':raise unittest.SkipTest('Linux fcntl agent; exercised on Linux CI and rehearsal host')
spec=importlib.util.spec_from_file_location('stack_server_agent',Path(__file__).resolve().parents[1]/'agents/server.py')
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)

class RecoveryTests(unittest.TestCase):
    def test_tar_traversal_and_symlinks_refused(self):
        for name,link in (('../escape',False),('data/link',True)):
            with tempfile.TemporaryDirectory() as d:
                base=Path(d);archive=base/'payload.tar.gz'
                with tarfile.open(archive,'w:gz') as out:
                    item=tarfile.TarInfo(name)
                    if link:item.type=tarfile.SYMTYPE;item.linkname='/etc/passwd';out.addfile(item)
                    else:item.size=1;out.addfile(item,io.BytesIO(b'x'))
                with self.assertRaisesRegex(RuntimeError,'unsafe_package_member'):agent.extract_payload(archive,base/'release')
                self.assertFalse((base/'release').exists())

    def test_sqlite_wal_backup_is_readable_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'active.db';dest=Path(d)/'saved.db'
            with contextlib.closing(sqlite3.connect(source)) as conn:
                conn.execute('PRAGMA journal_mode=WAL');conn.execute('CREATE TABLE events(value)');conn.execute('INSERT INTO events VALUES (42)');conn.commit()
                agent.backup_db(source,dest)
                self.assertEqual(conn.execute('SELECT value FROM events').fetchall(),[(42,)])
            with contextlib.closing(sqlite3.connect(dest)) as conn:self.assertEqual(conn.execute('SELECT value FROM events').fetchall(),[(42,)])

    def transaction(self,base):
        path=base/'compose.json';path.write_text('{}')
        t={'id':'own','backup':str(base/'backup'),'compose_path':str(path),'compose_before_sha256':None,'compose_after_sha256':agent.sha(path),'container_name':'clash-center-lab','new_container_id':'owned','old_container':None}
        agent.atomic(base/'transaction.json',t);return t

    def test_concurrent_compose_edit_refuses_before_any_command(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);t=self.transaction(base);Path(t['compose_path']).write_text('{"manual":true}')
            with patch.object(agent,'docker_info',return_value=None),patch.object(agent,'command') as command:
                with self.assertRaisesRegex(RuntimeError,'concurrent_compose_edit'):agent.restore({'site':'lab'},base)
                command.assert_not_called()
            self.assertTrue((base/'transaction.json').exists())

    def test_foreign_container_refuses_and_stale_guard_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);self.transaction(base)
            with patch.object(agent,'docker_info',return_value={'Id':'foreign'}),patch.object(agent,'command') as command:
                self.assertEqual(agent.restore({'site':'lab'},base,transaction='old')['reason'],'stale_guard')
                with self.assertRaisesRegex(RuntimeError,'identity_changed'):agent.restore({'site':'lab'},base)
                command.assert_not_called()

    def test_watchdog_bounds_restarts_and_respects_manual_stop(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);agent.atomic(base/'state.json',{'container_name':'clash-center-lab','container_id':'owned','manifest':{'image_id':'pinned'}})
            container={'Id':'owned','Image':'pinned','State':{'Running':True,'Health':{'Status':'unhealthy'}}}
            with patch.object(agent,'docker_info',return_value=container),patch.object(agent,'local_services_alive',return_value=False),patch.object(agent,'command',return_value=b'') as command,patch.object(agent.time,'time',return_value=10000):
                self.assertEqual(agent.watchdog({'site':'lab'},base)['action'],'none')
                self.assertEqual(agent.watchdog({'site':'lab'},base)['action'],'none')
                self.assertEqual(agent.watchdog({'site':'lab'},base)['action'],'restarted')
                for _ in range(5):self.assertEqual(agent.watchdog({'site':'lab'},base)['action'],'none')
                self.assertEqual(command.call_count,1)
                container['State']['Running']=False
                self.assertEqual(agent.watchdog({'site':'lab'},base)['reason'],'stopped')

    def test_upstream_readiness_failure_does_not_restart_local_services(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);agent.atomic(base/'state.json',{'container_name':'clash-center-lab','container_id':'owned','manifest':{'image_id':'pinned'}})
            x={'Id':'owned','Image':'pinned','State':{'Running':True,'Health':{'Status':'unhealthy'}}}
            with patch.object(agent,'docker_info',return_value=x),patch.object(agent,'local_services_alive',return_value=True),patch.object(agent,'command') as command:
                for _ in range(5):self.assertEqual(agent.watchdog({'site':'lab'},base)['reason'],'local_services_alive_dependency_or_readiness_failure')
                command.assert_not_called()

if __name__=='__main__':unittest.main()
