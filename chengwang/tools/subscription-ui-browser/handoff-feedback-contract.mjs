// Auxiliary runtime feedback policy; old evidence schemas remain unchanged.
import C from './handoff-feedback-contract.json' with {type:'json'}
import H from './handoff-negative-contract.json' with {type:'json'}
import {createHash} from 'node:crypto'
export {C}
const reject=()=>{throw Error('handoff feedback rejected')}
const need=v=>{if(!v)reject()}
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k))
const sha=raw=>createHash('sha256').update(raw).digest('hex')
export function validateSnapshot(value){
  need(exact(value,C.snapshotKeys)&&typeof value.status==='string'&&typeof value.alert==='string'&&Object.hasOwn(C.statusTexts,value.status)&&Object.hasOwn(C.alertTexts,value.alert)&&typeof value.statusVisible==='boolean'&&typeof value.alertVisible==='boolean')
  need((value.status!=='ABSENT'||!value.statusVisible)&&(value.alert!=='ABSENT'||!value.alertVisible));return value
}
export function observationFor(row,feedback){
  validateSnapshot(feedback);need(exact(row,H.domStepKeys)&&row.schema===H.domSchema&&Number.isSafeInteger(row.ordinal)&&row.ordinal>=1&&row.ordinal<=C.maxRows&&C.steps[row.ordinal-1]===row.step)
  const e=C.expected[row.step];need(e&&C.snapshotKeys.every(k=>feedback[k]===e[k]));need(feedback.alertVisible===row.dom.alertVisible&&feedback.statusVisible===(feedback.status!=='ABSENT'&&row.dom.pageVisible))
  const raw=Buffer.from(JSON.stringify(row)+'\n');need(raw.length<=H.maxDOMFileBytes)
  const result={schema:C.observationSchema,ordinal:row.ordinal,step:row.step,domRowSHA256:sha(raw),...feedback};validateObservation(result);return result
}
export function validateObservation(value){
  need(exact(value,C.observationKeys)&&value.schema===C.observationSchema&&Number.isSafeInteger(value.ordinal)&&value.ordinal>=1&&value.ordinal<=C.maxRows&&C.steps[value.ordinal-1]===value.step&&typeof value.domRowSHA256==='string'&&/^[a-f0-9]{64}$/.test(value.domRowSHA256))
  const feedback=Object.fromEntries(C.snapshotKeys.map(k=>[k,value[k]]));validateSnapshot(feedback);need(C.snapshotKeys.every(k=>feedback[k]===C.expected[value.step][k]));return value
}
export function observationLine(value){validateObservation(value);const raw=Buffer.from(C.prefix+JSON.stringify(value)+'\n');need(raw.length<=C.maxLineBytes&&/^[\x20-\x7e]+\n$/.test(raw.toString('utf8')));return raw}
export function validateProjection(raw,domRaw){
  need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=C.maxProjectionBytes&&raw.at(-1)===10&&Buffer.isBuffer(domRaw)&&domRaw.length>0&&domRaw.length<=H.maxDOMFileBytes&&domRaw.at(-1)===10)
  const lines=raw.toString('utf8').slice(0,-1).split('\n'),domLines=domRaw.toString('utf8').slice(0,-1).split('\n');need(lines.length===C.maxRows&&domLines.length===C.maxRows)
  return lines.map((line,i)=>{need(line.startsWith(C.prefix));const value=validateObservation(JSON.parse(line.slice(C.prefix.length))),dom=JSON.parse(domLines[i]);need(value.ordinal===i+1&&value.step===C.steps[i]&&observationLine(value).equals(Buffer.from(line+'\n'))&&value.domRowSHA256===sha(Buffer.from(domLines[i]+'\n'))&&JSON.stringify(dom)===domLines[i]);const expected=observationFor(dom,Object.fromEntries(C.snapshotKeys.map(k=>[k,value[k]])));need(observationLine(expected).equals(Buffer.from(line+'\n')));return value})
}
