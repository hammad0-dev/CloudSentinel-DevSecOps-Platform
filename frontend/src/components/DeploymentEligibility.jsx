import {useEffect,useState} from 'react';
import api from '../lib/api';
export function EligibilityStatus({result}){
 return <section className="card p-5 space-y-2"><h3 className="font-bold">AWS deployment eligibility</h3><p role="status">{result.decision}</p>{result.executionId&&<p>Pipeline execution #{result.executionId}</p>}<ul>{(result.reasons||[]).map(reason=><li key={reason}>{reason}</li>)}</ul>{result.expiresAt&&<p>Evidence expires: {result.expiresAt}</p>}<p>Eligibility is a security decision. AWS deployment has not started; automatic apply is disabled.</p></section>;
}
export default function DeploymentEligibility({projectId}){
 const [result,setResult]=useState({decision:'PENDING_EVIDENCE',reasons:['Loading evidence']});
 useEffect(()=>{let active=true;setResult({decision:'PENDING_EVIDENCE',reasons:['Loading evidence']});api.get(`/infrastructure/${projectId}/deployment-eligibility`).then(r=>{if(active)setResult(r.data)}).catch(()=>{if(active)setResult({decision:'BLOCKED',reasons:['Eligibility evidence unavailable']})});return()=>{active=false}},[projectId]);
 return <EligibilityStatus result={result}/>;
}
