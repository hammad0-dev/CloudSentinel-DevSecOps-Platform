'use strict';
function analyze(files){
 const languages=new Set(),frameworks=new Set(),databases=new Set(),ports=new Set(),components=[],evidence=[],warnings=[];
 const add=(file,role,name,kind='dependency')=>{components.push({file,role,name,kind,runtimeConfirmed:false});evidence.push(`${file}: ${name} (${role}; ${kind}, runtime not verified)`)};
 for(const [file,text] of Object.entries(files)){
  if(/(^|\/)package.json$/.test(file)){
   let p;try{p=JSON.parse(text)}catch{warnings.push(`${file}: invalid JSON; not interpreted`);continue}
   languages.add('JavaScript/TypeScript');
   for(const [name,version] of Object.entries({...p.devDependencies,...p.dependencies})){
    if(['react','react-dom','vue','next','@angular/core','svelte'].includes(name)){frameworks.add(name);add(file,'frontend',name)}
    if(['express','fastify','koa','@nestjs/core','hapi','@hapi/hapi'].includes(name)){frameworks.add(name);add(file,'backend',name)}
    if(['pg','postgres','psycopg','mysql2','mongoose','mongodb','redis','sqlite3','better-sqlite3'].includes(name)){databases.add(({pg:'PostgreSQL',postgres:'PostgreSQL',mysql2:'MySQL',mongoose:'MongoDB',mongodb:'MongoDB',redis:'Redis',sqlite3:'SQLite','better-sqlite3':'SQLite'})[name]||name);add(file,'database-client',name)}
   }
   if(!components.some(c=>c.file===file))evidence.push(`${file}: JavaScript manifest; application role unknown`);
  }
  if(/requirements[^/]*\.txt$|pyproject.toml$|Pipfile$|setup.cfg$/.test(file)){
   languages.add('Python');const clean=text.split('\n').filter(l=>!/^\s*#/.test(l)).join('\n');
   for(const name of ['fastapi','flask','django','starlette'])if(new RegExp(`(?:^|[\\s"'])${name}(?:[\\s"'=<>~!\\[]|$)`,'im').test(clean)){frameworks.add(name);add(file,'backend',name)}
   for(const [name,db] of [['psycopg2','PostgreSQL'],['psycopg2-binary','PostgreSQL'],['psycopg','PostgreSQL'],['asyncpg','PostgreSQL'],['pymysql','MySQL'],['pymongo','MongoDB'],['redis','Redis']])if(new RegExp(`(?:^|[\\s"'])${name}(?:[\\s"'=<>~!\\[]|$)`,'im').test(clean)){databases.add(db);add(file,'database-client',name)}
   evidence.push(`${file}: Python dependency manifest; clients do not prove a deployed database`);
  }
  if(/pom.xml$|build.gradle/.test(file)){languages.add('Java');if(/spring-boot/.test(text)){frameworks.add('Spring Boot');add(file,'backend','Spring Boot')}}
  if(/go.mod$/.test(file)){languages.add('Go');evidence.push(`${file}: Go module; application role unknown`)}
  if(/\.html?$/.test(file)&&/<!doctype\s+html|<html[\s>]/i.test(text)){languages.add('HTML');add(file,'frontend','Static HTML','source')}
  if(/Dockerfile[^/]*$/i.test(file)){
   add(file,'infrastructure','Dockerfile','build declaration');for(const m of text.matchAll(/^\s*EXPOSE\s+(\d+)/gmi))if(+m[1]>0&&+m[1]<65536)ports.add(+m[1]);
  }
  if(/(?:docker-)?compose[^/]*\.ya?ml$/i.test(file)){
   add(file,'infrastructure','Docker Compose','service declaration');
   let inside=false,service=null;for(const line of text.split('\n')){
    if(/^services:\s*(?:#.*)?$/.test(line)){inside=true;continue}
    if(inside&&/^\S/.test(line)&&!/^#/.test(line)){inside=false;service=null}
    if(!inside)continue;
    const m=/^  ([\w-]+):\s*(?:#.*)?$/.exec(line);if(m){service=m[1];add(file,'service',service,'Compose declaration');continue}
    const image=/^    image:\s*["']?([^\s"'#]+)/.exec(line);if(service&&image){const name=image[1].split('/').pop().split(':')[0];const db={postgres:'PostgreSQL',mysql:'MySQL',mariadb:'MySQL',mongo:'MongoDB',redis:'Redis'}[name];if(db){databases.add(db);add(file,'database-service',db,'Compose image declaration')}}
   }
   warnings.push(`${file}: only simple block-style service/image declarations interpreted; YAML aliases and dynamic values require review`);
  }
 }
 const frontend=components.some(c=>c.role==='frontend'),backend=components.some(c=>c.role==='backend'),dbClient=components.some(c=>c.role==='database-client'),dbService=components.some(c=>c.role==='database-service');
 const declared=components.filter(c=>c.role==='service').length;
 let architecture='unknown',confidence='low',reason='Insufficient application evidence; language or container declarations alone do not establish tiers.';
 if(frontend&&backend&&(dbClient||dbService)){architecture='three-tier';confidence=dbService?'high':'medium';reason='Frontend and backend components plus database evidence suggest three logical tiers; runtime topology is unverified.'}
 else if(backend&&(dbClient||dbService)||frontend&&backend){architecture='two-tier';confidence='medium';reason=backend&&(dbClient||dbService)?'Backend plus database dependency/service suggests two logical tiers.':'Frontend and backend suggest two logical tiers; database not established.'}
 else if(frontend&&!dbClient&&!dbService||backend&&!dbClient&&!dbService){architecture='one-tier';confidence='medium';reason='One application role detected, with no database dependency established in inspected files; this is not proof of absence.'}
 else if(declared>1){architecture='custom';reason='Multiple declared services lack sufficient role evidence to infer standard tiers.'}
 return {architecture,confidence,reason,confirmationRequired:true,languages:[...languages],frameworks:[...frameworks],databases:[...databases],ports:[...ports],components,evidence,warnings,confirmedRuntimeServices:[],supportedTemplate:'network-only',applicationDeploymentSupported:false,limitations:'Repository declarations only, not confirmed runtime services. Networking-only template; no application, compute or database deployment.'};
}
module.exports={analyze};
