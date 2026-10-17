'use strict';
// Explicit offline fixture; never imported by production runtime code.
const {STORAGE,expectedAddons}=require('../../services/zapInitialization');
module.exports=function initializationEvidence(imageId='sha256:'+'a'.repeat(64)) {
  const MiB=1024*1024;
  const writable=require('../../config/zap-writable-paths.json');
  return {imageId,version:'2.17.0',complete:true,extensionsLoaded:true,observationExitCode:0,
    logsComplete:true,logsTruncated:false,startupLog:'Extensions loaded\nZAP is now listening on 127.0.0.1:8090',
    storage:{homeWritable:true,uid:1000,gid:1000,mode:'0700',readOnlyRootfs:true,
      homeCapacityBytes:STORAGE.homeMiB*MiB,homeAvailableBytes:200*MiB,
      memoryLimitBytes:STORAGE.memoryMiB*MiB,javaMaxHeapBytes:STORAGE.javaHeapMiB*MiB,totalTmpfsLimitBytes:516*MiB,
      profile:{path:writable.profilePath,capacityBytes:4*MiB,uid:1000,gid:1000,mode:'0700',writable:true,seedSha256:writable.profileSeed.sha256,seedMode:'0600'},
      javaPreferences:{rootProperty:writable.javaPreferencesRoot,path:writable.javaPreferencesEffectivePath,uid:1000,gid:1000,mode:'0700',writable:true}},
    listeners:{complete:true,tcpComplete:true,tcp6Complete:true,listeners:[{family:'IPv6',address:'127.0.0.1',port:8090,nativeAddress:'0000000000000000FFFF00000100007F'}]},
    policy:{name:'Default Policy',xmlParsed:true,apiLoaded:true,complete:true,bytes:1024,sha256:'b'.repeat(64)},
    installedAddons:Object.entries(expectedAddons).map(([id,version])=>({id,version,installationStatus:'INSTALLED'})),
    loadedAddonIds:Object.keys(expectedAddons),activeRuleIds:[...require('../../config/active-zap-image-manifest.json').requiredPluginIds]};
};
