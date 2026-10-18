#!/usr/bin/env node
'use strict';
const fs=require('node:fs/promises');
const {assess,verifySignature}=require('../services/networkReviewPackage');
async function privateRead(file){const st=await fs.lstat(file);if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)||st.size>1024*1024)throw Error('Unsafe file');return fs.readFile(file)}
async function main(){
 const [reviewFile,snapshotFile,signatureFile,keyFile]=process.argv.slice(2);if(!reviewFile||!snapshotFile)throw Error('Usage');
 const bytes=await privateRead(reviewFile),review=JSON.parse(bytes),snapshotBytes=await privateRead(snapshotFile),record=JSON.parse(snapshotBytes),snapshot=record.discovery||record;
 if(review.discoveryEvidence?.reference?.sha256!==require('node:crypto').createHash('sha256').update(snapshotBytes).digest('hex'))throw Error('Snapshot hash mismatch');
 const {Reservations}=require('../services/cidrReservations'),store=new Reservations(),rows=await store.load();
 const local=JSON.parse(process.env.INFRA_RESERVED_CIDRS||'[]');if(!Array.isArray(local))throw Error('Invalid ranges');
 const result=assess(review,snapshot,[...local,...rows.filter(r=>store.active(r)).map(r=>r.cidr)]);
 let authenticatedAttestation=false;
 if(signatureFile&&keyFile&&process.env.INFRA_NETWORK_REVIEW_TRUST_FILE)authenticatedAttestation=verifySignature(bytes,await privateRead(signatureFile),await privateRead(keyFile),JSON.parse(await privateRead(process.env.INFRA_NETWORK_REVIEW_TRUST_FILE)),review.administratorArn);
 if(!authenticatedAttestation)result.blockers.push('TRUSTED_ADMINISTRATOR_SIGNATURE_MISSING_OR_INVALID');
 result.valid=result.valid&&authenticatedAttestation;console.log(JSON.stringify({...result,status:result.valid?'LOCAL_VALIDATION_PASS':'BLOCKED',authenticatedAttestation,awsCalls:0,configurationChanges:0},null,2));process.exitCode=result.valid?0:2;
}
if(require.main===module)main().catch(()=>{console.error('BLOCKED: supply private valid review/snapshot files; optional signature/key require configured administrator trust. No changes made.');process.exitCode=2});
