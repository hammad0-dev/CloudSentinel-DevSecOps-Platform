'use strict';
// Explicit offline fixture; never imported by production runtime code.
const {STORAGE,expectedAddons}=require('../../services/zapInitialization');
module.exports=function initializationEvidence(imageId='sha256:'+'a'.repeat(64)) {
  const MiB=1024*1024;
  return {imageId,version:'2.17.0',complete:true,extensionsLoaded:true,observationExitCode:0,
    logsComplete:true,logsTruncated:false,startupLog:'Extensions loaded\nZAP is now listening on 127.0.0.1:8090',
    storage:{homeWritable:true,uid:1000,gid:1000,mode:'0700',readOnlyRootfs:true,
      homeCapacityBytes:STORAGE.homeMiB*MiB,homeAvailableBytes:200*MiB,
      memoryLimitBytes:STORAGE.memoryMiB*MiB,javaMaxHeapBytes:STORAGE.javaHeapMiB*MiB,totalTmpfsLimitBytes:512*MiB},
    policy:{name:'Default Policy',xmlParsed:true,apiLoaded:true,complete:true,bytes:1024,sha256:'b'.repeat(64)},
    installedAddons:Object.entries(expectedAddons).map(([id,version])=>({id,version,installationStatus:'INSTALLED'})),
    loadedAddonIds:Object.keys(expectedAddons),activeRuleIds:[...require('../../config/active-zap-image-manifest.json').requiredPluginIds]};
};
