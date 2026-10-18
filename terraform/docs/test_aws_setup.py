"""Offline policy/renderer checks; never calls AWS or provisions resources."""
import importlib.util,json,pathlib,tempfile,unittest,argparse
root=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('renderer',root/'render_aws_setup.py');renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
class SetupTests(unittest.TestCase):
 def args(self,out):return argparse.Namespace(project_id=88,az='ap-south-1a',state_bucket='unit-test-state-bucket',flow_log_bucket='unit-test-flow-bucket',state_admin_arn='arn:aws:iam::229032674007:role/UnitTestAdmin',default_sg_arn=None,output=out)
 def test_render_local_private_and_no_unresolved_values(self):
  with tempfile.TemporaryDirectory() as tmp:
   out=pathlib.Path(tmp)/'rendered';r=renderer.render(self.args(str(out)));self.assertEqual(r['awsCalls'],0);self.assertFalse(r['approvalGranted']);self.assertEqual(out.stat().st_mode&0o777,0o700)
   for f in out.iterdir():self.assertEqual(f.stat().st_mode&0o777,0o600);self.assertNotIn('APPROVED_',f.read_text())
   self.assertFalse((out/'default-sg-adoption.json').exists());self.assertEqual(json.load(open(out/'approved.tfvars.json'))['project_id'],88)
 def test_existing_directory_never_overwritten(self):
  with tempfile.TemporaryDirectory() as tmp:
   with self.assertRaises(FileExistsError):renderer.render(self.args(tmp))
 def test_protected_projects_invalid_buckets_and_region_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   for key,value in [('project_id',11),('project_id',17),('project_id',0),('az','us-east-1a'),('state_bucket','bad/target'),('flow_log_bucket','unit-test-state-bucket')]:
    a=self.args(str(pathlib.Path(tmp)/'output'));setattr(a,key,value)
    with self.assertRaises(ValueError):renderer.render(a)
 def test_no_mutation_wildcard_resources_or_admin_grants(self):
  for name in ['network-create-read.json','network-manage.json','default-sg-adoption.json','terraform-state-runtime.json','flow-log-delivery-runtime.json']:
   d=json.load(open(root/'policies'/name))
   for s in d['Statement']:
    self.assertEqual(s['Effect'],'Allow');self.assertNotIn('*',s['Action']);self.assertNotIn('iam:PassRole',s['Action'])
    if s['Resource']=='*':
     self.assertTrue(all(a.startswith('ec2:Describe') or a in ['logs:CreateLogDelivery','logs:DeleteLogDelivery'] for a in s['Action']));self.assertEqual(s['Condition']['StringEquals']['aws:RequestedRegion'],'ap-south-1')
 def test_state_delete_only_exact_lock(self):
  d=json.load(open(root/'policies'/'terraform-state-runtime.json'))
  for s in d['Statement']:
   if 's3:DeleteObject' in s['Action']:self.assertTrue(s['Resource'].endswith('.tflock'))
 def test_state_access_requires_expected_account_and_tls(self):
  d=json.load(open(root/'policies'/'terraform-state-runtime.json'))
  for statement in d['Statement']:
   self.assertEqual(statement['Condition']['StringEquals']['s3:ResourceAccount'],'229032674007')
   self.assertEqual(statement['Condition']['Bool']['aws:SecureTransport'],'true')
 def test_default_sg_requires_exact_future_approval(self):
  d=json.load(open(root/'policies'/'default-sg-adoption.json'))
  self.assertTrue(all(s['Resource']=='APPROVED_NEW_VPC_DEFAULT_SECURITY_GROUP_ARN' for s in d['Statement']))
 def test_policy_size_below_managed_limit(self):
  for n in ['network-create-read.json','network-manage.json','default-sg-adoption.json','terraform-state-runtime.json','flow-log-delivery-runtime.json']:
   self.assertLessEqual(len(json.dumps(json.load(open(root/'policies'/n)),separators=(',',':'))),6144)
 def test_log_bucket_source_and_prefix_restricted(self):
  d=json.load(open(root/'policies'/'flow-log-bucket-policy.json'))
  for s in d['Statement']:
   if s['Effect']=='Allow':
    self.assertEqual(s['Principal'],{'Service':'delivery.logs.amazonaws.com'});self.assertEqual(s['Condition']['StringEquals']['aws:SourceAccount'],'229032674007');self.assertEqual(s['Condition']['ArnLike']['aws:SourceArn'],'arn:aws:logs:ap-south-1:229032674007:*')
    if s['Action']=='s3:PutObject':self.assertTrue(s['Resource'].endswith('/AWSLogs/229032674007/*'))
if __name__=='__main__':unittest.main()
