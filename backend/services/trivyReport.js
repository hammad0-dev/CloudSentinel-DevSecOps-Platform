'use strict';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
// Trivy tags Results with json:",omitempty". An absent array is legitimate only
// for a successful filesystem or Git repository report with artifact evidence.
function filesystemReport(report) {
 if(!object(report)||report.SchemaVersion!==2)throw Error('Invalid Trivy report: expected SchemaVersion 2');
 if(report.ArtifactType!==undefined&&!['filesystem','repository'].includes(report.ArtifactType))throw Error('Invalid Trivy report: unexpected artifact type');
 let results=report.Results;
 if(results===undefined) {
  if(!['filesystem','repository'].includes(report.ArtifactType)||typeof report.ArtifactName!=='string'||!report.ArtifactName.trim())throw Error('Invalid Trivy report: missing filesystem artifact evidence');
  results=[];
 }
 if(!Array.isArray(results))throw Error('Invalid Trivy report: Results must be an array');
 for(const result of results) {
  if(!object(result))throw Error('Invalid Trivy report: malformed result');
  for(const field of ['Packages','Vulnerabilities','Misconfigurations'])if(result[field]!==undefined&&(!Array.isArray(result[field])||!result[field].every(object)))throw Error(`Invalid Trivy report: malformed ${field}`);
 }
 return {...report,Results:results};
}
function cycloneDxReport(report) {
 if(!object(report)||report.bomFormat!=='CycloneDX'||!/^1\.[3-7]$/.test(report.specVersion||''))throw Error('Invalid CycloneDX SBOM');
 let components=report.components;
 if(components===undefined){if(!object(report.metadata?.component))throw Error('Invalid CycloneDX SBOM: missing root component evidence');components=[];}
 if(!Array.isArray(components)||!components.every(object))throw Error('Invalid CycloneDX SBOM: components must be an array');
 return {...report,components};
}
module.exports={filesystemReport,cycloneDxReport};
