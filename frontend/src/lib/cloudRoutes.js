export function routeTableLabel(table,network){
 const associated=(network.subnets||[]).filter(s=>(table.subnets||[]).includes(s.id));
 const defaults=(table.routes||[]).filter(r=>r.destination==='0.0.0.0/0'||r.destination==='::/0');
 if(defaults.some(r=>r.state==='active'&&(network.internetGateways||[]).some(g=>g.id===r.target)))return 'Public route table';
 if(associated.length&&!defaults.length)return 'Private route table';
 return 'Route table (routing requires review)';
}
