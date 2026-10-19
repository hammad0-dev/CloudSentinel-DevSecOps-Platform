"use strict";
const data=require('../../config/compliance/owasp-cwes.json');
const docker=require('../../config/compliance/cis-docker.json');
const OWASP_VERSION='OWASP Top 10:2021'; // Compatibility default; 2025 is separately selectable.
const OWASP_VERSIONS=['2021','2025'];
const owasp=data.categories.filter(c=>c.version==='2021');
function checkId(value) {
 const match=/^(?:AVD-)?DS-?0*(\d+)$/i.exec(String(value||''));
 return match?`DS${match[1].padStart(4,'0')}`:null;
}
const cis=docker.controls.map(c=>({...c,framework:docker.name,frameworkId:docker.id,benchmarkId:docker.id,version:docker.version,
 rules:c.check?[c.check]:[],applicableScanner:'Trivy config',targetTechnology:docker.targetTechnology,
 assessmentMethod:c.check?'Explicit configuration check outcome':'External/manual assessment required',
 expectedEvidence:c.check?`Project-linked Dockerfile, exact ${c.check} result and completed scan timestamp`:'No supported automatic evidence adapter',
 supportStatus:c.check?'SUPPORTED_STATIC_CHECK':'UNSUPPORTED',reference:docker.reference,remediationReference:docker.reference,scope:docker.scope}));
function mapFinding(f) {
 const refs=[...new Set((f.references||f.references_json||[]).map(r=>String(r).toUpperCase()))];
 const mappings=new Map();
 function add(category,basis,rule,source=category.mappingSource) {
  const key=`${category.frameworkId}:${category.id}`;
  if(mappings.has(key)) {
   const m=mappings.get(key);if(!m.mappingRules.includes(rule)){m.mappingRules.push(rule);m.basis+='; '+basis;}return;
  }
  mappings.set(key,{framework:category.framework,frameworkName:'OWASP Top 10',frameworkId:category.frameworkId,id:category.id,name:category.name,version:category.version,findingId:f.id?String(f.id):null,basis,mappingRules:[rule],mappingSource:source,reference:category.reference,registryRevision:data.revision});
 }
 for(const category of data.categories) {
  const matched=refs.filter(r=>/^CWE-\d+$/.test(r)&&category.cwes.includes(Number(r.slice(4))));
  for(const reference of matched)add(category,`Published category CWE association: ${reference}`,reference);
 }
 if(['DEPENDENCY','IMAGE'].includes(f.source)&&refs.some(r=>/^CVE-\d{4}-\d+$/.test(r))) {
  for(const id of ['A06:2021','A03:2025'])add(data.categories.find(c=>c.id===id),'Scanner records a known component CVE; component vulnerability indicator','KNOWN_COMPONENT_CVE');
 }
 const control=f.source==='IAC'?cis.find(c=>c.check&&c.check===checkId(f.identity)):null;
 if(control) {
  for(const id of ['A05:2021','A02:2025'])add(data.categories.find(c=>c.id===id),`Verified configuration classification from exact Trivy ${control.check}`,control.check,docker.reference);
  const key=`${docker.id}:${control.id}`;
  mappings.set(key,{framework:docker.name,frameworkName:docker.name,frameworkId:docker.id,benchmarkId:docker.id,version:docker.version,id:control.id,name:control.name,findingId:f.id?String(f.id):null,basis:`Exact Trivy ${control.check}; related Dockerfile failure evidence. Mapping alone is not a control assessment.`,mappingRules:[control.check],mappingSource:docker.reference,reference:docker.reference,kind:'FINDING_MAPPING'});
 }
 // Internal, explicit associations to CIS Controls v8. These are control gaps,
 // not assertions that every safeguard or benchmark requirement was assessed.
 const associations=[];
 if(f.classification==='VULNERABILITY'&&['SAST','DEPENDENCY','IMAGE','DAST','ACTIVE_DAST'].includes(f.source)&&refs.some(r=>/^(CVE-\d{4}-\d+|CWE-\d+)$/.test(r)))associations.push(['CIS-16','Application Software Security','VERIFIED_VULNERABILITY']);
 if(f.source==='IAC'&&control)associations.push(['CIS-4','Secure Configuration',control.check]);
 if(refs.some(r=>['CWE-200','CWE-201','CWE-312','CWE-319','CWE-321','CWE-798'].includes(r)))associations.push(['CIS-3','Data Protection','EXPLICIT_DATA_PROTECTION_CWE']);
 for(const [id,name,rule] of associations)mappings.set(`cis-controls-v8:${id}`,{framework:'CIS Controls',frameworkId:'cis-controls-v8',version:'8',id,name,kind:'CONTROL_ASSOCIATION',findingId:f.id?String(f.id):null,basis:`Internal evidence association: ${rule}. Indicates a potential control gap; not a whole-control or benchmark assessment.`,mappingRules:[rule],mappingSource:'CloudSentinel explicit association rules v1',reference:'https://www.cisecurity.org/controls/v8'});
 return [...mappings.values()];
}
module.exports={OWASP_VERSION,OWASP_VERSIONS,owasp,cis,docker,checkId,mapFinding,categories:data.categories};
