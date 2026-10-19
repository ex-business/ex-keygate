#!/usr/bin/env python3
"""Test ownership/cleanup boundaries using a fake Docker CLI and isolated files."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent
FAKE = r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
record=Path(os.environ['KEYGATE_FAKE_STATE'])
args=sys.argv[1:]
if args[0]=='run':
 name=args[args.index('--name')+1]
 record.write_text(json.dumps({'name':name,'removed':False,'labels':{'keygate.purpose':'development','keygate.instance':name}}))
 if os.environ.get('KEYGATE_FAKE_RACE'):
  target=record.parent/'data'/'dev-console'/'database-url';target.write_text('another-session');target.chmod(0o600)
elif args[0]=='exec':pass
elif args[0]=='inspect':
 state=json.loads(record.read_text())
 print(json.dumps([{'Config':{'Labels':state['labels']},'NetworkSettings':{'Ports':{'5432/tcp':[{'HostPort':'54399'}]}}}]))
elif args[0]=='rm':
 state=json.loads(record.read_text());state['removed']=True;record.write_text(json.dumps(state))
else:sys.exit(2)
'''

class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='keygate-db-script-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'scripts').mkdir()
        for name in ['start-dev-db.py','stop-dev-db.py']:
            shutil.copyfile(SOURCE/name,self.root/'scripts'/name)
        self.bin=self.root/'bin';self.bin.mkdir()
        docker=self.bin/'docker';docker.write_text(FAKE);docker.chmod(0o700)
        self.env=os.environ.copy();self.env['PATH']=str(self.bin)+os.pathsep+self.env['PATH']
        self.env['KEYGATE_FAKE_STATE']=str(self.root/'state.json')
        self.folder=self.root/'data'/'dev-console'
    def run_script(self,name):
        return subprocess.run([sys.executable,str(self.root/'scripts'/name)],env=self.env,capture_output=True,text=True,timeout=10)
    def test_reuse_refusal_and_label_checked_cleanup(self):
        self.assertEqual(self.run_script('start-dev-db.py').returncode,0)
        password_file=self.folder/'database-url';original=password_file.read_bytes()
        self.assertEqual(password_file.stat().st_mode & 0o777,0o600)
        self.assertNotEqual(self.run_script('start-dev-db.py').returncode,0)
        self.assertTrue(password_file.read_bytes()==original,"Private configuration was changed")
        record=self.root/'state.json';state=json.loads(record.read_text());state['labels']['keygate.purpose']='other';record.write_text(json.dumps(state))
        self.assertNotEqual(self.run_script('stop-dev-db.py').returncode,0)
        self.assertTrue(password_file.exists())
        self.assertFalse(json.loads(record.read_text())['removed'])
        state['labels']['keygate.purpose']='development';record.write_text(json.dumps(state))
        self.assertEqual(self.run_script('stop-dev-db.py').returncode,0)
        self.assertFalse(password_file.exists())
        self.assertTrue(json.loads(record.read_text())['removed'])
    def test_failed_racing_setup_preserves_other_session_file(self):
        self.env['KEYGATE_FAKE_RACE']='1'
        self.assertNotEqual(self.run_script('start-dev-db.py').returncode,0)
        self.assertEqual((self.folder/'database-url').read_text(),'another-session')
        self.assertTrue(json.loads((self.root/'state.json').read_text())['removed'])

if __name__=='__main__':unittest.main()
