"use strict";
const crypto=require('crypto');
const {mapFinding}=require('./registry');
const SOURCES=['SAST','DEPENDENCY','IAC','IMAGE','DAST','ACTIVE_DAST'];
const SEVERITIES=['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'];
const STATUSES=['OPEN','RESOLVED','ACCEPTED_RISK','FALSE_POSITIVE'];
function severity(value) {
 const s=String(value||'').toUpperCase();
 return ({BLOCKER:'CRITICAL',MAJOR:'HIGH',MINOR:'LOW',INFORMATIONAL:'INFO'}[s])||(SEVERITIES.includes(s)?s:'UNKNOWN');
}
function clean(value) {
 return String(value??'').replace(/<[^>]*>/g,'').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g,'')
 .replace(/\b(?:authorization|cookie|password|token|secret|api[_-]?key)\s*[:=]\s*[^\r\n,;]*/gi,'[REDACTED]')
 .replace(/(https?:\/\/)[^/@\s]+:[^/@\s]+@/gi,'$1[REDACTED]@').slice(0,8000);
}
function safeEndpoint(value) {try {const u=new URL(value);u.username='';u.password='';u.search='';u.hash='';return u.toString();}catch{return clean(value).split('?')[0];}}
function normalize(source,row,scan) {
 if(source==='DEPENDENCY'&&!row.cve_id)return null;
 if(source==='SAST'&&['BUG','CODE_SMELL'].includes(row.issue_type))return null;
 let identity,title,description,location,remediation,classification='VULNERABILITY';
 let references=[];
 if(source==='SAST') {
  identity=row.rule||'unclassified';title=row.message||row.rule||'SAST finding';description=row.message;
  location=`${row.file_path||''}${row.line_number?`:${row.line_number}`:''}`;
  classification=row.issue_type==='VULNERABILITY'?'VULNERABILITY':row.issue_type==='SECURITY_HOTSPOT'?'HOTSPOT_REVIEW':'UNCLASSIFIED_REVIEW';
  if(classification==='HOTSPOT_REVIEW'&&['SAFE','FIXED'].includes(row.hotspot_review))return null;
  remediation='Review the source rule and affected code in SonarQube; validate the fix with a new scan.';
  references=String(row.rule||'').match(/CWE-\d+/gi)||[];
 } else if(source==='DEPENDENCY'||source==='IMAGE') {
  identity=row.cve_id||row.vulnerability_id; title=row.title||`${identity} in ${row.pkg_name||row.package_name}`;
  description=row.description||row.title;
  location=`${row.pkg_type||row.package_type||'package'}:${row.pkg_name||row.package_name}@${row.pkg_version||row.installed_version||'unknown'}`;
  if(source==='IMAGE')location=`${scan.resource||'image'} / ${location}`;
  remediation=row.fixed_version?`Upgrade to the vendor fixed version: ${row.fixed_version}.`:'No fixed version recorded; review the vendor advisory and available mitigations.';
  references=[identity];
 } else if(source==='IAC') {
  identity=row.misconfig_id||row.misconfig_type||'unknown';title=row.misconfig_type||identity;description=row.description;
  location=`${row.config_file||''}${row.start_line?`:${row.start_line}`:''}`;remediation=row.resolution;classification='MISCONFIGURATION';
 } else {
  identity=row.plugin_id||row.attack_type||row.alert||'unknown';title=row.alert;description=row.alert;
  location=`${row.method||'GET'} ${safeEndpoint(row.endpoint)} ${row.param||''}`.trim();remediation=row.solution;
  if(Number(row.cwe_id)>0)references=[`CWE-${row.cwe_id}`];
 }
 const f={source,identity:clean(identity),title:clean(title)||'Unnamed finding',description:clean(description),severity:severity(row.severity),location:clean(location),remediation:clean(remediation)||'Review scanner evidence and apply the relevant vendor mitigation.',references:[...new Set(references.map(r=>clean(r).toUpperCase()))],classification};
 // Severity, timestamps and unstable row IDs deliberately do not form identity.
 f.fingerprint=crypto.createHash('sha256').update(JSON.stringify([scan.project_id,source,f.identity,f.location])).digest('hex');
 f.mappings=mapFinding(f);
 f.evidence={sourceTable:scan.detailTable,sourceRecordId:String(row.id??row.finding_fingerprint??f.fingerprint),scanId:String(scan.scan_id),scanMode:clean(scan.mode),rule:f.identity,originalSeverity:clean(row.severity),issueType:clean(row.issue_type),hotspotReview:clean(row.hotspot_review)};
 return f;
}
module.exports={SOURCES,SEVERITIES,STATUSES,severity,normalize,clean};
