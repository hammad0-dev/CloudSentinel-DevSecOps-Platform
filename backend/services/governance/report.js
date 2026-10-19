"use strict";
const {clean}=require('./normalize');
function csvCell(value) {
 let s=clean(value);if(/^[\s]*[=+\-@]/.test(s))s="'"+s;
 return '"'+s.replace(/"/g,'""')+'"';
}
function csv(findings) {
 const keys=['id','title','project_name','severity','source','location','status','first_seen','last_seen','identity','remediation','mapping_ids','mapping_explanations'];
 findings=findings.map(f=>({...f,mapping_ids:(f.mappings||[]).map(m=>`${m.frameworkId||m.framework} ${m.id}`).join('; '),mapping_explanations:(f.mappings||[]).map(m=>m.basis).join('; ')}));
 return '\uFEFF'+[keys.map(csvCell).join(','),...findings.map(f=>keys.map(k=>csvCell(f[k] instanceof Date?f[k].toISOString():f[k])).join(','))].join('\r\n');
}
function complianceRows(snapshot) {
 const compliance=snapshot.compliance;
 return (compliance.projectControls||[]).flatMap(c=>{
  const evidence=c.evidence?.length?c.evidence:[null];
  return evidence.map(e=>({project:c.project_name,benchmark:c.framework,benchmark_version:c.version,control:c.id,title:c.name,status:c.status,
   support:c.supportStatus,assessment_date:c.assessedAt||'',resource:e?.resource||'',source_scan:e?.scan_id||'',check:e?.check_id||'',
   finding_id:e?.finding_id||'',evidence_status:e?.status||'',evidence:e?JSON.stringify(e.evidence):'No supporting evidence',remediation:c.remediation,
   pass_rate:compliance.metrics?.passRate??'Not assessed',coverage:compliance.metrics?.coverage??'Not assessed',methodology:compliance.metrics?.methodology||''}));
 });
}
function complianceCsv(snapshot) {
 const keys=['project','benchmark','benchmark_version','control','title','status','support','assessment_date','resource','source_scan','check','finding_id','evidence_status','evidence','remediation','pass_rate','coverage','methodology'];
 return '\uFEFF'+[keys.map(csvCell).join(','),...complianceRows(snapshot).map(row=>keys.map(k=>csvCell(row[k])).join(','))].join('\r\n');
}
function pdf(snapshot,kind) {
 const PDFDocument=require('pdfkit');
 return new Promise((resolve,reject)=>{
  const doc=new PDFDocument({size:'A4',margin:48,bufferPages:true,info:{Title:`CloudSentinel ${kind} report`,Author:'CloudSentinel'}});
  const chunks=[];doc.on('data',c=>chunks.push(c));doc.on('error',reject);doc.on('end',()=>resolve(Buffer.concat(chunks)));
  const text=v=>clean(v).replace(/[^\x20-\x7e\n\r]/g,' ');
  function heading(value){if(doc.y>700)doc.addPage();doc.moveDown(0.7).font('Helvetica-Bold').fontSize(14).fillColor('#123652').text(text(value));doc.moveDown(0.3);}
  function line(value){doc.font('Helvetica').fontSize(10).fillColor('#202d38').text(text(value),{lineGap:3});}
  doc.font('Helvetica-Bold').fontSize(24).fillColor('#123652').text('CloudSentinel');
  heading(kind==='security'?'Security Assessment Report':'Compliance Evidence Report');
  line(`Scope: ${snapshot.filters.project?snapshot.projects.map(p=>p.name).join(', '):'All authorized projects'}`);
  line(`Generated (UTC): ${snapshot.generatedAt}`);
  line(`Observation range (UTC): ${snapshot.filters.from||'earliest available'} to ${snapshot.filters.to||'latest available'}`);
  line(`Stored scan date range: ${snapshot.scanDateRange?.earliest?new Date(snapshot.scanDateRange.earliest).toISOString():'unavailable'} to ${snapshot.scanDateRange?.latest?new Date(snapshot.scanDateRange.latest).toISOString():'unavailable'}`);
  line(`Active filters: ${JSON.stringify(snapshot.filters)}`);
  heading('Executive summary');
  line(`${kind==='compliance'?(snapshot.compliance.uniqueVulnerabilities??snapshot.total):snapshot.total} unique findings. ${snapshot.byStatus.map(x=>`${x.name}: ${x.value}`).join('; ')}.`);
  line(`Security posture: ${snapshot.score.value===null?'Not assessed':snapshot.score.value+'/100'}. Complete assessment slots: ${snapshot.score.assessedSlots}/${snapshot.score.totalSlots}.`);
  heading('Severity breakdown');
  line(snapshot.bySeverity.map(x=>`${x.name}: ${x.value}`).join(' | '));
  heading('Scan coverage');
  if(!snapshot.recentScans.length)line('No imported assessment records in the selected scope.');
  for(const s of snapshot.recentScans)line(`${s.project_name} | ${s.source} #${s.scan_id} | ${new Date(s.scanned_at).toISOString()} | ${s.details_complete?'Details verified':'Incomplete or unavailable historical details'} | ${s.source_status}`);
  if(kind==='compliance') {
   const overall=snapshot.compliance.overall;
   if(overall){heading('Overall compliance assessment');line(`Compliance pass rate: ${overall.passRate===null?'Not assessed':overall.passRate+'%'}. Coverage: ${overall.coverage===null?'Not assessed':overall.coverage+'%'}. PASS ${overall.PASS}; FAIL ${overall.FAIL}; NOT_ASSESSED ${overall.NOT_ASSESSED}; ERROR ${overall.ERROR}.`);line(overall.methodology);}
   const matching=snapshot.compliance.matching;
   if(matching){line(`OWASP categories matched: ${matching.owasp.matched}/${matching.owasp.total} (${matching.owasp.percentage}%).`);line(`CIS Controls v8 matched: ${matching.cisControls.matched}/${matching.cisControls.total} (${matching.cisControls.percentage}%). Supported association rules: ${matching.cisControls.supportedMappingControls}.`);line(`Docker checks with findings: ${matching.docker.matched}/${matching.docker.total} (${matching.docker.percentage}%).`);}
   const ow=snapshot.compliance.owaspMetrics;if(ow)line(`OWASP project-category slots: PASS ${ow.PASS}; FAIL ${ow.FAIL}; NOT_ASSESSED ${ow.NOT_ASSESSED}. Pass rate: ${ow.passRate===null?'Not assessed':ow.passRate+'%'}. Coverage: ${ow.coverage}%.`);
   heading(snapshot.compliance.version);
   for(const c of snapshot.compliance.owasp){line(`${c.id} | ${c.name} | ${c.findings} mapped findings | ${c.status||'NOT_ASSESSED'}`);line(`Severity: ${JSON.stringify(c.bySeverity||{})}. Projects: ${(c.projects||[]).map(p=>p.name).join(', ')||'None'}`);}
   line(`Unmapped findings: ${snapshot.compliance.unmapped}`);
   heading('CIS Controls v8 associations (not benchmark assessments)');
   for(const c of snapshot.compliance.cisControls||[])line(`${c.id} | ${c.name} | ${c.findings} mapped findings | ${c.unresolved} unresolved | ${c.status}`);
   for(const b of snapshot.compliance.benchmarks||[]) {heading(`${b.name} ${b.version} - registered subset`);line(b.scope);}
   const metric=snapshot.compliance.metrics;
   if(metric){line(`Pass rate: ${metric.passRate===null?'Not assessed':metric.passRate+'%'}. Assessment coverage: ${metric.coverage===null?'Not assessed':metric.coverage+'%'}. Assessed applicable controls: ${metric.assessed}/${metric.applicable}.`);line(metric.methodology);}
   for(const c of snapshot.compliance.cis){line(`${c.id} | ${c.name} | ${c.assessment} | ${c.findings} supporting findings`);line(`Recommendation: ${c.remediation}`);}
   line(JSON.stringify(snapshot.compliance.cisSummary));
   heading('Project controls and supporting assessment evidence');
   for(const c of snapshot.compliance.projectControls||[]){line(`${c.project_name} | ${c.id} | ${c.status} | ${c.supportStatus} | ${c.assessedAt?new Date(c.assessedAt).toISOString():'Not assessed'}`);for(const e of c.evidence||[])line(`Resource: ${e.resource} | Scan ${e.scan_id} | ${e.check_id} ${e.status} | ${JSON.stringify(e.evidence)}`);}
   heading('Compliance gaps and limitations');line(snapshot.compliance.limitations);
  } else {
   heading('Highest priority unresolved issues');
   if(!snapshot.priority.length)line('No unresolved findings in this selection; assessment limitations still apply.');
   for(const f of snapshot.priority)line(`#${f.id} ${f.severity} | ${f.project_name} | ${f.title}`);
  }
  heading('Scoring methodology and assessment limitations');line(snapshot.score.methodology);
  line('Only stored scanner evidence is included. Missing historical details are not reconstructed. Kubernetes audits lack owner/project identity and are excluded. Source scans do not establish full benchmark coverage. No official compliance or certification is asserted. Manual finding status is current, including for historical date filters.');
  heading('Finding details and remediation');
  if(!snapshot.findings.length)line('No findings match the selected filters. This does not prove the absence of vulnerabilities.');
  for(const f of snapshot.findings) {
   heading(`#${f.id} - ${f.title}`);
   line(`${f.project_name} | ${f.source} | ${f.severity} | ${f.status} | ${f.classification}`);
   line(`Identity: ${f.identity}. Scan: ${f.scan_id}. Observed: ${new Date(f.observed_at).toISOString()}`);
   line(`Location: ${f.location||'Not supplied'}`);line(f.description);
   line(`References: ${f.references_json.join(', ')||'None supplied'}`);
   line(`Remediation: ${f.remediation}`);
   line(`Mappings: ${f.mappings.map(m=>`${m.framework} ${m.version} ${m.id} (${m.basis})`).join('; ')||'Not mapped'}`);
  }
  const range=doc.bufferedPageRange();
  for(let i=range.start;i<range.start+range.count;i++) {
   doc.switchToPage(i);const bottom=doc.page.margins.bottom;doc.page.margins.bottom=0;
   doc.font('Helvetica').fontSize(8).fillColor('#657786').text(`CloudSentinel | ${kind} report | Page ${i+1} of ${range.count}`,48,doc.page.height-30,{lineBreak:false});doc.page.margins.bottom=bottom;
  }
  doc.end();
 });
}
module.exports={csv,csvCell,pdf,complianceCsv,complianceRows};
