"""V4 settings, public-repository guards and safe orchestration units."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import batch
import interactive
import presign
import vault
import workflow as w

PASSWORD='Public V4 workflow test password'  # Non-production test vector.


def settings(root):
    return {'version':1,'data_dir':str(root/'data'),'vault_file':str(root/'data/vault.enc'),'vault_id':'a'*32,
            'batches':[{'input_dir':str(root/'videos'),'output_dir':str(root/'encrypted'),'private_dir':str(root/'private')}],
            'active_batch':0,'sources':[{'id':'r2','name':'My storage','remote':'r2:private-bucket'}],'active_source':'r2',
            'vault_remote':'public:public-bucket/vault.enc','vault_url':'https://vault.example.invalid/vault.enc',
            'site_url':'https://player.example.invalid/','expires':'6d','repo_dir':'','deployment_linked':False,'deploy_branch':'','approved_local_paths':[]}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.s=settings(self.root);self.local=w.LocalStore(self.root/'config')
        self.local.path.mkdir(mode=0o700);(self.root/'videos').mkdir();(self.root/'data').mkdir(mode=0o700)
        self.raw=vault.create(PASSWORD);self.s['vault_id']=vault.parse(self.raw).vault_id.hex()
        Path(self.s['vault_file']).write_bytes(self.raw)

    def test_settings_private_atomic_bounded_and_no_secret_fields(self):
        self.local.save_settings(self.s);self.assertEqual(self.local.settings(),self.s)
        self.assertEqual((self.local.path/'settings.json').stat().st_mode&0o777,0o600)
        newer=copy.deepcopy(self.s);newer['expires']='5d';self.local.save_settings(newer)
        self.assertEqual(json.loads((self.local.path/'settings.json.bak').read_text()),self.s)
        for key,value in [('password','not allowed'),('key','not allowed'),('access','not allowed')]:
            bad=copy.deepcopy(self.s);bad[key]=value
            with self.assertRaises(ValueError):self.local.save_settings(bad)
        bad=copy.deepcopy(self.s);bad['vault_url']+='?X-Amz-Signature=not-allowed'
        with self.assertRaises(ValueError):self.local.save_settings(bad)
        (self.local.path/'settings.json').write_text('{broken')
        with self.assertRaises(ValueError):self.local.settings()
        self.assertEqual(Path(self.s['vault_file']).read_bytes(),self.raw)

    def test_saved_settings_symlink_and_parallel_session_rejected(self):
        self.local.save_settings(self.s);path=self.local.path/'settings.json';path.unlink();path.symlink_to(self.root/'data/vault.enc')
        with self.assertRaises(OSError):self.local.settings()
        with self.local.session():
            with self.assertRaises(w.UserError):
                with self.local.session():pass

    def test_one_and_multiple_storage_choices_do_not_read_credentials(self):
        app=interactive.App(self.local)
        with patch('interactive.ask',side_effect=['private-bucket']),patch('interactive.confirm',return_value=True),patch('sys.stdout',io.StringIO()):
            chosen=app.source_select({'r2':'s3'})
        self.assertEqual(chosen['remote'],'r2:private-bucket')
        with patch('interactive.ask',side_effect=['2','private-bucket']),patch('interactive.confirm',return_value=True),patch('sys.stdout',io.StringIO()):
            second=app.source_select({'r2':'s3','b2':'b2'})
        self.assertEqual(second['remote'],'b2:private-bucket');self.assertNotEqual(chosen['id'],second['id'])
        with self.assertRaises(ValueError):app.source_select({'local':'local'})

    def test_watch_does_not_scan_encrypt_import_or_upload_videos(self):
        opened=vault.unlock(self.raw,PASSWORD);library=w.Library(self.s,self.local,emit=lambda _:None)
        target=library.publication(w.sha(self.raw));library.state['published']=target;library.save()
        with patch('batch.scan',side_effect=AssertionError('no scan')),patch('batch.batch_encrypt',side_effect=AssertionError('no encryption')),patch('batch.batch_add',side_effect=AssertionError('no import')),patch('workflow.upload_object',side_effect=AssertionError('no video upload')):
            with vault.VaultFile(self.s['vault_file']) as store:raw,newer,signed=library.watch(opened,self.raw,store)
        self.assertEqual(raw,self.raw);self.assertFalse(signed)

    def test_trusted_unchanged_plan_never_hashes_completed_video(self):
        source=self.root/'videos/a.mp4';source.write_bytes(b'video bytes')
        with patch('sys.stderr',io.StringIO()):batch.batch_encrypt(source.parent,self.root/'encrypted',self.root/'private')
        library=w.Library(self.s,self.local,emit=lambda _:None);entries,_=library.records();library.verify_local(entries)
        with patch('batch.fingerprint',side_effect=AssertionError('no video hash')),patch('vault.verify_video',side_effect=AssertionError('no video authentication')):
            plan=library.plan();self.assertFalse(plan['new']);self.assertEqual(plan['unverified'],0)

    def test_folder_change_preserves_old_work_and_vault(self):
        self.local.save_settings(self.s);app=interactive.App(self.local);app.s=copy.deepcopy(self.s)
        folder=self.root/'second';folder.mkdir()
        with patch('interactive.ask',side_effect=['1',str(folder),'0']),patch('interactive.confirm',return_value=True),patch('sys.stdout',io.StringIO()):app.settings()
        self.assertEqual(len(app.s['batches']),2);self.assertEqual(app.s['batches'][0],self.s['batches'][0])
        self.assertEqual(Path(self.s['vault_file']).read_bytes(),self.raw)

    def test_backup_restore_creates_new_file_and_preserves_current_key(self):
        self.local.save_settings(self.s);app=interactive.App(self.local);app.s=copy.deepcopy(self.s)
        backup=self.root/'backup.enc';backup.write_bytes(self.raw)
        with patch('interactive.ask',return_value=str(backup)),patch('interactive.password',return_value=PASSWORD),patch('interactive.confirm',return_value=True),patch('sys.stdout',io.StringIO()):app.restore()
        self.assertNotEqual(app.s['vault_file'],self.s['vault_file'])
        self.assertEqual(Path(self.s['vault_file']).read_bytes(),self.raw)
        new=vault.unlock(Path(app.s['vault_file']).read_bytes(),PASSWORD);old=vault.unlock(self.raw,PASSWORD)
        self.assertEqual(new.key,old.key);self.assertGreater(new.meta.revision,old.meta.revision)

    def test_no_parameter_non_tty_is_clear_failure_and_advanced_cli_still_works(self):
        env={**os.environ,'XDG_CONFIG_HOME':str(self.root/'unused-config')}
        p=subprocess.run([sys.executable,str(ROOT/'vault.py')],stdin=subprocess.DEVNULL,capture_output=True,text=True,env=env)
        self.assertEqual(p.returncode,1);self.assertIn('交互式终端',p.stderr);self.assertFalse((self.root/'unused-config').exists())
        p=subprocess.run([sys.executable,str(ROOT/'vault.py'),'--help'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0);self.assertIn('batch-encrypt',p.stdout);self.assertIn('presign',p.stdout)

    def test_site_confirmation_is_not_reused_for_a_different_website(self):
        state=w.empty_state()
        replies=[(200,{},b'{"vaultSchemas":[1,2,3]}'),(200,{},w.web_bytes(self.s))]
        with patch('workflow.fetch',side_effect=replies):self.assertTrue(w.website_ready(self.s,self.local,state))
        with patch('workflow.fetch',side_effect=AssertionError('reuse confirmed site')):
            self.assertTrue(w.website_ready(self.s,self.local,state))
        changed=copy.deepcopy(self.s);changed['site_url']='https://different.example.invalid/'
        with patch('workflow.fetch',return_value=(404,{},b'')) as fetch:
            self.assertFalse(w.website_ready(changed,self.local,state));self.assertEqual(fetch.call_count,1)


class GitSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.repo=self.root/'repo';self.repo.mkdir();self.remote=self.root/'remote.git'
        subprocess.run(['git','init','--bare',str(self.remote)],check=True,capture_output=True)
        self.command('init','--initial-branch=main');self.command('config','user.name','SecureS3 Test');self.command('config','user.email','test@example.invalid')
        (self.repo/'web').mkdir();(self.repo/'web/config.js').write_text((ROOT/'web/config.js').read_text())
        (self.repo/'README.md').write_text('public repo fixture\n');(self.repo/'.gitignore').write_text('private/\n*.key\n.config.js.lock\n')
        self.command('add','--','web/config.js','README.md','.gitignore');self.command('commit','-m','initial public fixture')
        self.command('remote','add','origin',str(self.remote));self.command('push','-u','origin','main')
        self.s=settings(self.root);self.s.update(repo_dir=str(self.repo),deployment_linked=True,deploy_branch='main')
        self.local=w.LocalStore(self.root/'config');self.local.path.mkdir(mode=0o700);self.state=w.empty_state()
    def command(self,*args):
        return subprocess.run(['git','-C',str(self.repo),*args],check=True,capture_output=True,text=True).stdout.strip()
    def remote_head(self):return self.command('ls-remote','origin','refs/heads/main').split()[0]

    def test_actual_git_push_commits_only_allowlisted_public_configuration(self):
        before=self.remote_head();w.config_target(self.s,self.state,True);self.local.save_state(self.state)
        w.push_config(self.s,self.local,self.state)
        after=self.remote_head();self.assertNotEqual(before,after)
        self.assertEqual(self.command('diff-tree','--no-commit-id','--name-only','-r',after),'web/config.js')
        self.assertEqual(self.command('status','--porcelain'),'')
        content=self.command('show',after+':web/config.js');self.assertNotIn('X-Amz',content);self.assertNotIn('key',json.dumps(w.web_data(self.s)).lower())

    def test_dirty_workspace_is_never_overwritten_or_pushed(self):
        before=(self.repo/'web/config.js').read_bytes();head=self.remote_head();(self.repo/'unrelated.txt').write_text('user changes')
        with self.assertRaises(w.UserError):w.config_target(self.s,self.state,True)
        self.assertEqual((self.repo/'web/config.js').read_bytes(),before);self.assertEqual(self.remote_head(),head)

    def test_tracked_private_material_blocks_auto_commit_even_if_ignored(self):
        key=self.repo/'private/example.key';key.parent.mkdir();key.write_text('public test sentinel')
        paths=['private/example.key','rclone.conf.backup','state.json.bak','SETTINGS.JSON']
        for name in paths[1:]:(self.repo/name).write_text('non-production scanner sentinel')
        self.command('add','-f','--',*paths);self.command('commit','-m','simulated unsafe tracked files')
        self.assertEqual(set(paths),set(w.sensitive_tracked(self.repo)))
        with self.assertRaises(w.UserError):w.config_target(self.s,self.state,True)
        with self.assertRaises(w.UserError):w.private_path_risk(key)

    def test_unpublished_or_forged_history_cannot_escape_file_allowlist(self):
        old=self.remote_head();(self.repo/'unrelated.txt').write_text('unpublished content')
        self.command('add','--','unrelated.txt');self.command('commit','-m','not generated config')
        w.config_target(self.s,self.state,True)
        with self.assertRaises(w.UserError):w.push_config(self.s,self.local,self.state)
        self.state['config_commit']=self.command('rev-parse','HEAD')
        with self.assertRaises(w.UserError):w.push_config(self.s,self.local,self.state)
        self.assertEqual(self.remote_head(),old)

    def test_runtime_git_push_confirmation_defaults_to_no(self):
        app=interactive.App(self.local);app.s=self.s;old=self.remote_head()
        with patch('workflow.generate_site',return_value=self.root/'website'),patch('interactive.confirm',return_value=False) as question,patch('sys.stdout',io.StringIO()):app.configure_website()
        self.assertFalse(question.call_args.kwargs.get('default',False));self.assertEqual(self.remote_head(),old)
        self.assertEqual(self.command('diff','--name-only'),'web/config.js')


if __name__=='__main__':unittest.main()
