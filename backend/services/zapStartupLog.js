'use strict';
// Parse ZAP's elapsed-time Log4j records and Java Util Logging records.
// Continuation lines belong to the originating record; rule titles are data.
const passiveUrl='http://[a-z0-9-]+\\.test:18080/test/(?:sqli\\?id=1|xss\\?q=hello)';
const requestProgress=new RegExp('^\\t?Job requestor (?:set (?:url = '+passiveUrl+'|method = GET|responseCode = 200)|requesting URL '+passiveUrl+')$');
const passiveProgress=line=>requestProgress.test(line)||/^\t?Job passiveScan-wait set maxDuration = 1$/.test(line)||/^\t?Job report set (?:template = traditional-json|reportDir = \/tmp|reportFile = report-[01]\.json)$/.test(line)||/^\t?Job report generated report \/tmp\/report-[01]\.json$/.test(line);
// Execution 32 native records: exact byte lengths and SHA-256 are retained in
// zap-active-progress-e32.json. Recognizing progress never proves scan success.
const activeProgress=line=>/^\t?Job activeScan-policy set (?:name = cloudsentinel-active-fixture-v1|defaultStrength = Low|defaultThreshold = Off|default strength to LOW|default threshold to OFF|rule (?:40012|40014|40016|40017|40018|40019|40020) (?:strength|threshold) to LOW)$/.test(line)||/^\t?Job activeScan set (?:context = cloudsentinel-active-fixture|policy = cloudsentinel-active-fixture-v1|maxScanDurationInMins = 1|maxRuleDurationInMins = 1|maxAlertsPerRule = 10|threadPerHost = 1|delayInMs = 500)$/.test(line);
function analyze(text){
 const records=[];let current=null,unknown=0;
 const malformed=typeof text!=='string'||/\r(?!\n)|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text);
 for(const [index,line] of String(text||'').split(/\r?\n/).entries()){
  if(!line.trim())continue;
  const zap=/^\d+\s+\[[^\]\r\n]+\]\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\S+\s+-\s+(.+)$/.exec(line);
  const jul=/^(INFO|WARNING|SEVERE|CONFIG|FINE|FINER|FINEST):\s*(.+)$/.exec(line);
  if(zap||jul){const m=zap||jul;current={level:m[1],text:m[2],lines:[line]};records.push(current);continue;}
  if(/^[A-Z][a-z]{2} \d{1,2}, \d{4} .+ (?:AM|PM) [\w.$]+ \w+$/.test(line))continue;
  if(current&&/^(?:\s+at |\s*Caused by: |\s*Suppressed: |\s*\.\.\. \d+ more|(?:[\w$]+\.)+[\w$]*(?:Exception|Error)(?::|$))/.test(line)){current.text+='\n'+line;current.lines.push(line);continue;}
  if(/^(?:Found Java version \d|Read custom JVM args from |Using JVM args: |Extensions loaded$|ZAP is now listening on 127\.0\.0\.1:\d+)/.test(line)){current={level:'INFO',text:line,lines:[line]};records.push(current);continue;}
  // Automation 0.60.0 Messages.properties: automation.info.jobstart/jobend
  // and automation.out.title.good. This is format recognition, not job success
  // evidence: command exit, parsed report and all runtime gates remain required.
  if(/^(?:Automation plan succeeded!|\t?Job [A-Za-z0-9_.-]+ started|\t?Job [A-Za-z0-9_.-]+ finished, time taken: \d{2}:\d{2}:\d{2})$/.test(line)||passiveProgress(line)||activeProgress(line)){current={level:'INFO',text:line,lines:[line]};records.push(current);continue;}
  // Unstructured known failure messages are still failures, never benign text.
  current={level:'UNKNOWN',text:line,lines:[line],lineNumber:index+1};records.push(current);unknown++;
 }
 let failure=null;const failures=[];
 for(const record of records){
  const t=record.text;
  const ruleTitle=['INFO','DEBUG','TRACE'].includes(record.level)&&/^Loaded (?:passive|active) scan rule: [^\r\n]+$/.test(t);
  if(ruleTitle)continue;
  let code=null;
  if(/No space left on device|\bENOSPC\b|Disk quota exceeded/i.test(t))code='ZAP_STORAGE_EXHAUSTED';
  else if(/\.mozilla\/firefox\/[\s\S]*Read-only file system|Read-only file system[\s\S]*\.mozilla\/firefox\//i.test(t))code='ZAP_PROFILE_NOT_READY';
  else if(/Couldn't create user preferences directory|User preferences are unusable|Could not (?:lock User prefs|change permissions on userRoot)|BackingStoreException/i.test(t))code='ZAP_PREFERENCES_NOT_READY';
  else if(/Premature end of file|SAXParseException|Error parsing.*\.policy|Broken JBroFuzz Installation/i.test(t))code='ZAP_INITIALIZATION_CORRUPT';
  else if(['ERROR','FATAL','SEVERE'].includes(record.level)||/Failed to (?:install|load|initialise|initialize)|Unable to save the configuration|Read-only file system|Permission denied|BindException|Address already in use|not found|Unrecognized option|File type is not supported/i.test(t))code='ZAP_INITIALIZATION_FAILED';
  else if(record.level==='UNKNOWN'&&/(?:Exception|Error)(?::|$)/.test(t))code='ZAP_INITIALIZATION_FAILED';
  if(code){failure=failure||code;failures.push(record);}
 }
 if(!failure&&(!records.length||unknown||malformed))failure='ZAP_STARTUP_LOG_UNVERIFIED';
 return {failure,records,failures,unknownRecords:unknown,malformed};
}
module.exports={analyze};
