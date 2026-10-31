"""V4 terminal E2E against real rclone and a local TLS object store."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import vault
import batch
import workflow as w
from interactive_fixture import Store, PASSWORD


@unittest.skipUnless(shutil.which('rclone'),'rclone required for actual terminal/object-store E2E')
class InteractiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.store=Store(self.root);self.addCleanup(self.store.close);self.terminals=[]
    def tearDown(self):
        forbidden=[PASSWORD.encode(),b'NONPRODUCTIONTESTSECRET',b'X-Amz-Signature']
        for terminal in self.terminals:
            for secret in forbidden:self.assertNotIn(secret,terminal.data)
        for name in ('settings.json','settings.json.bak','state.json','state.json.bak'):
            file=self.store.home/name
            if file.exists():
                for secret in forbidden:self.assertNotIn(secret,file.read_bytes())
    def start(self):
        terminal=self.store.cli();self.addCleanup(terminal.close);self.terminals.append(terminal);return terminal
    def settings(self):return json.loads((self.store.home/'settings.json').read_text())
    def raw(self):return Path(self.settings()['vault_file']).read_bytes()
    def complete_setup(self):
        terminal=self.start();terminal.setup(self.store);terminal.expect('全部完成',90);terminal.menu();return terminal
    def quit(self,terminal):terminal.send('0');self.assertEqual(terminal.process.wait(timeout=5),0)
    def video_puts(self):return [p for m,p in self.store.operations if m=='PUT' and p.startswith('/private-bucket/')]

    def test_first_wizard_real_upload_watch_and_second_launch_no_repeat_questions(self):
        terminal=self.complete_setup();raw=self.raw();opened=vault.unlock(raw,PASSWORD)
        self.assertEqual(len(opened.data['files']),2);self.assertEqual(len(self.video_puts()),2)
        self.assertEqual(raw,self.store.objects['/public-bucket/vault.enc'])
        self.assertNotIn(PASSWORD.encode(),terminal.data);self.assertNotIn(b'X-Amz-Signature',terminal.data)
        self.assertNotIn(b'NONPRODUCTIONTESTSECRET',terminal.data)
        self.assertEqual(terminal.data.count('设置主密码'.encode()),1);self.assertNotIn('请输入主密码'.encode(),terminal.data)
        settings=self.settings();self.assertNotIn('access',settings);self.assertNotIn('X-Amz',json.dumps(settings))
        self.assertFalse(Path(settings['vault_file']).is_relative_to(ROOT))
        count=len(self.store.operations);terminal.send('1');terminal.expect('已经是最新状态');terminal.menu()
        self.assertEqual(count,len(self.store.operations));self.assertEqual(self.raw(),raw)
        self.quit(terminal)
        again=self.start();again.menu();self.assertNotIn('私人 Bucket'.encode(),again.data);self.assertNotIn('你的视频文件夹'.encode(),again.data)
        again.send('2');again.expect('请输入主密码');again.send(PASSWORD);again.expect('已准备好');again.menu()
        self.assertEqual(len(self.video_puts()),2);self.assertEqual(self.raw(),raw);self.quit(again)

    def test_upload_interruption_resumes_only_unconfirmed_objects(self):
        self.store.fail_video_after=1;terminal=self.start();terminal.setup(self.store)
        terminal.expect('上传未完成',60);terminal.menu();before=self.raw()
        settings=self.settings();private=Path(settings['batches'][0]['private_dir'])
        manifest=json.loads((private/'manifest.json').read_text());ids=[i['id'] for i in manifest['files']]
        self.assertEqual(len(ids),2);self.assertEqual(len(vault.unlock(before,PASSWORD).data['files']),0)
        self.store.fail_video_after=None;terminal.send('1');terminal.expect('是否安全继续');terminal.send('y')
        terminal.expect('请输入主密码');terminal.send(PASSWORD);terminal.expect('全部完成',60);terminal.menu()
        self.assertEqual([i['id'] for i in json.loads((private/'manifest.json').read_text())['files']],ids)
        puts=self.video_puts();self.assertEqual(sum(p.endswith(ids[0]+'.enc') for p in puts),1)
        self.assertEqual(len(vault.unlock(self.raw(),PASSWORD).data['files']),2);self.quit(terminal)

    def test_signing_failure_keeps_imported_keys_and_no_partial_grants(self):
        terminal=self.start();terminal.setup(self.store);terminal.expect('[4/5]',60);self.store.fail_sign=True
        terminal.expect('操作未完成',30);terminal.menu();opened=vault.unlock(self.raw(),PASSWORD)
        self.assertEqual(len(opened.data['files']),2);self.assertTrue(all('access' not in f for f in opened.data['files']))
        self.assertNotIn('/public-bucket/vault.enc',self.store.objects);before_puts=len(self.video_puts())
        self.store.fail_sign=False;terminal.send('1');terminal.expect('是否安全继续');terminal.send('y')
        terminal.expect('请输入主密码');terminal.send(PASSWORD);terminal.expect('全部完成',60);terminal.menu()
        self.assertEqual(len(self.video_puts()),before_puts)
        newer=vault.unlock(self.raw(),PASSWORD);self.assertEqual(newer.key,opened.key)
        self.assertEqual([f['key'] for f in newer.data['files']],[f['key'] for f in opened.data['files']]);self.quit(terminal)

    def test_publication_failure_watch_retries_without_scan_upload_or_resign(self):
        self.store.fail_public=True;terminal=self.start();terminal.setup(self.store)
        terminal.expect('远端发布失败',60);terminal.menu();raw=self.raw();before=len(self.video_puts())
        private_heads=sum(m=='HEAD' and p.startswith('/private-bucket/') for m,p in self.store.operations)
        self.store.videos.rename(self.root/'source-offline')
        self.store.fail_public=False;terminal.send('2');terminal.expect('请输入主密码');terminal.send(PASSWORD)
        terminal.expect('已准备好',60);terminal.menu()
        self.assertEqual(raw,self.raw());self.assertEqual(before,len(self.video_puts()))
        self.assertEqual(private_heads,sum(m=='HEAD' and p.startswith('/private-bucket/') for m,p in self.store.operations))
        self.assertEqual(self.store.objects['/public-bucket/vault.enc'],raw);self.quit(terminal)

    def test_expired_watch_refreshes_without_touching_source_or_video_uploads(self):
        terminal=self.complete_setup();self.quit(terminal);raw=self.raw();opened=vault.unlock(raw,PASSWORD)
        files=copy.deepcopy(opened.data['files'])
        for f in files:
            for grant in f['access'].values():grant['expiresAt']=int(time.time())-1
        expired=vault.update(opened,files);Path(self.settings()['vault_file']).write_bytes(expired)
        self.store.videos.rename(self.root/'source-unavailable');before=len(self.video_puts())
        head_before=sum(m=='HEAD' and p.startswith('/private-bucket/') for m,p in self.store.operations)
        watch=self.start();watch.menu();watch.send('2');watch.expect('请输入主密码');watch.send(PASSWORD)
        watch.expect('已准备好',60);watch.menu();new=vault.unlock(self.raw(),PASSWORD)
        self.assertEqual(new.key,opened.key);self.assertEqual([f['key'] for f in new.data['files']],[f['key'] for f in opened.data['files']])
        self.assertEqual(before,len(self.video_puts()));self.assertGreater(sum(m=='HEAD' and p.startswith('/private-bucket/') for m,p in self.store.operations),head_before)
        self.quit(watch)

    def test_incremental_new_file_skips_completed_files_and_changed_source_conflicts(self):
        terminal=self.complete_setup();settings=self.settings();original=vault.unlock(self.raw(),PASSWORD)
        old_ids={f['id'] for f in original.data['files']};before=len(self.store.operations)
        (self.store.videos/'新增.mp4').write_bytes(b'new video bytes')
        terminal.send('1');terminal.expect('是否添加这 1');terminal.send('y');terminal.expect('请输入主密码');terminal.send(PASSWORD)
        terminal.expect('全部完成',60);terminal.menu()
        new=vault.unlock(self.raw(),PASSWORD);self.assertEqual(len(new.data['files']),3)
        self.assertTrue(old_ids <= {f['id'] for f in new.data['files']})
        operations=self.store.operations[before:]
        self.assertFalse(any(m in ('PUT','GET') and any(p.endswith(i+'.enc') for i in old_ids) for m,p in operations))
        raw=self.raw();count=len(self.store.operations);(self.store.videos/'电影 0.mp4').write_bytes(b'changed')
        terminal.send('1');terminal.expect('源视频已修改');terminal.menu()
        self.assertEqual(raw,self.raw());self.assertEqual(count,len(self.store.operations));self.quit(terminal)

    def test_existing_vault_reused_and_missing_configured_vault_never_reinitialized(self):
        self.store.data.mkdir(parents=True,mode=0o700)
        raw=vault.create(PASSWORD);path=self.store.data/'vault.enc';path.write_bytes(raw);path.chmod(0o600)
        terminal=self.start();terminal.expect('将验证后复用');terminal.expect('视频的私人 Bucket');terminal.send('private-bucket')
        terminal.expect('已确认视频存储');terminal.send('y');terminal.expect('公开发布位置');terminal.send('v4test:public-bucket/vault.enc')
        terminal.expect('稳定 HTTPS');terminal.send(self.store.url+'/public-bucket/vault.enc');terminal.expect('播放器网站');terminal.send(self.store.url+'/site/')
        terminal.expect('你的视频文件夹');terminal.send(str(self.store.videos));terminal.expect('请输入主密码');terminal.send(PASSWORD)
        terminal.expect('现在添加视频');terminal.send('n');terminal.menu();self.assertEqual(path.read_bytes(),raw);self.quit(terminal)
        path.rename(path.with_suffix('.saved'));again=self.start();again.expect('不会重新初始化');again.menu();self.assertFalse(path.exists())
        self.assertNotIn('设置主密码'.encode(),again.data);self.quit(again)

    def test_diagnostics_report_unverified_failures_and_do_not_change_privacy(self):
        terminal=self.complete_setup();self.store.cors=False;self.store.public_private=True
        terminal.send('3');terminal.expect('7. 高级选项');terminal.expect('请选择 [0]');terminal.send('6')
        terminal.expect('开始检查');terminal.send('y');terminal.expect('请输入主密码');terminal.send(PASSWORD)
        terminal.expect('可复制的 CORS');terminal.expect('7. 高级选项')
        self.assertIn('失败：私人视频拒绝匿名读取'.encode(),terminal.data)
        self.assertIn('未验证：浏览器跨域权限'.encode(),terminal.data)
        self.assertTrue(self.store.public_private);self.assertFalse(self.store.cors)
        terminal.expect('请选择 [0]');terminal.send('0');terminal.menu();self.quit(terminal)

    def test_multiple_remotes_can_be_selected_in_the_actual_terminal(self):
        config=self.root/'rclone.conf';original=config.read_text()
        config.write_text(original+'\n'+original.replace('[v4test]','[v4other]'))
        terminal=self.start();terminal.setup(self.store,storage_choice='2')
        terminal.expect('全部完成',90);terminal.menu()
        self.assertEqual(self.settings()['sources'][0]['remote'],'v4test:private-bucket')
        self.assertEqual(len(self.video_puts()),2);self.quit(terminal)

    def test_stale_public_readback_never_reports_success_or_reuploads_confirmed_vault(self):
        self.store.stale_public=b'outdated encrypted vault';terminal=self.start();terminal.setup(self.store)
        terminal.expect('旧版本或不同内容',60);terminal.menu();raw=self.raw()
        state=json.loads((self.store.home/'state.json').read_text())
        self.assertIsNone(state['published']);self.assertIsNotNone(state['uploaded'])
        before=len([p for m,p in self.store.operations if m=='PUT'])
        self.store.stale_public=None;terminal.send('2');terminal.expect('请输入主密码');terminal.send(PASSWORD)
        terminal.expect('已准备好',60);terminal.menu()
        self.assertEqual(before,len([p for m,p in self.store.operations if m=='PUT']))
        self.assertEqual(self.raw(),raw);self.quit(terminal)


if __name__=='__main__':unittest.main()
