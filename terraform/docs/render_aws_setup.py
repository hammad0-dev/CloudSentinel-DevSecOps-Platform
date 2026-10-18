#!/usr/bin/env python3
"""Render approval-dependent setup files locally. Makes no AWS/network calls."""
import argparse,json,os,pathlib,re

def render(args):
    if args.project_id <= 0 or args.project_id in (11,17):
        raise ValueError('Approved project ID must be positive and cannot be 11/17')
    if not re.fullmatch(r'ap-south-1[a-z]',args.az):
        raise ValueError('Expected an ap-south-1 AZ; availability must be independently checked')
    for b in [args.state_bucket,args.flow_log_bucket]:
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]',b):
            raise ValueError('Use a valid simple S3 bucket name (no dots)')
    if args.state_bucket == args.flow_log_bucket:
        raise ValueError('State and flow logs require separate buckets')
    if not re.fullmatch(r'arn:aws:iam::229032674007:(?:role|user)/[\w+=,.@/\-]+',args.state_admin_arn):
        raise ValueError('An explicit state administrator identity in the intended account is required')
    if args.state_admin_arn == 'arn:aws:iam::229032674007:user/cloudsentinel-dev':
        raise ValueError('State administrator must be separate from the Terraform runtime user')
    if args.default_sg_arn and not re.fullmatch(r'arn:aws:ec2:ap-south-1:229032674007:security-group/sg-[0-9a-f]+',args.default_sg_arn):
        raise ValueError('Exact approved new-VPC default SG ARN required')
    out=pathlib.Path(args.output).expanduser();out.mkdir(mode=0o700,parents=False,exist_ok=False)
    os.chmod(out,0o700)
    replacements={'APPROVED_PROJECT_ID':str(args.project_id),'APPROVED_STATE_BUCKET':args.state_bucket,'APPROVED_FLOW_LOG_BUCKET':args.flow_log_bucket,'APPROVED_STATE_ADMINISTRATOR_ARN':args.state_admin_arn}
    if args.default_sg_arn:replacements['APPROVED_NEW_VPC_DEFAULT_SECURITY_GROUP_ARN']=args.default_sg_arn
    for f in (pathlib.Path(__file__).parent/'policies').glob('*.json'):
        if f.name=='default-sg-adoption.json' and not args.default_sg_arn:continue
        text=f.read_text()
        for old,new in replacements.items():text=text.replace(old,new)
        data=json.loads(text)
        if 'APPROVED_' in text:raise ValueError('Unresolved approval placeholder')
        fd=os.open(out/f.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as h:h.write(json.dumps(data,indent=2)+'\n')
    key=f'cloudsentinel/projects/{args.project_id}/network/terraform.tfstate'
    files={'approved.backend.hcl':f'bucket = "{args.state_bucket}"\nkey = "{key}"\nprofile = "cloudsentinel-dev"\n','approved.tfvars.json':json.dumps({'project_id':args.project_id,'availability_zone':args.az,'environment':'development','vpc_cidr':'10.0.0.0/16','flow_log_destination_arn':f'arn:aws:s3:::{args.flow_log_bucket}'},indent=2)+'\n'}
    for name,text in files.items():
        fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as h:h.write(text)
    return {'rendered':str(out),'awsCalls':0,'approvalGranted':False,'defaultSgAdoptionReady':bool(args.default_sg_arn)}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project-id',type=int,required=True);p.add_argument('--az',required=True)
    p.add_argument('--state-bucket',required=True);p.add_argument('--flow-log-bucket',required=True)
    p.add_argument('--state-admin-arn',required=True);p.add_argument('--default-sg-arn')
    p.add_argument('--output',required=True)
    args=p.parse_args()
    try:print(json.dumps(render(args),indent=2))
    except (ValueError,OSError) as e:p.exit(1,f'Render blocked: {e}\n')
