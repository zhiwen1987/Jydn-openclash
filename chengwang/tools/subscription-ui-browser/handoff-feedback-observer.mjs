// Read-only, same-task projection. Only enums/booleans cross the browser boundary.
import {C,observationFor,observationLine} from './handoff-feedback-contract.mjs'
import {writeSync} from 'node:fs'
export function collectFeedback(config){
  const need=value=>{if(!value)throw Error('handoff feedback rejected')}
  const panels=[...document.querySelectorAll('section.subscriptions[aria-label="订阅资源工作区"]')];need(panels.length===1);const panel=panels[0]
  const statuses=[...panel.querySelectorAll('[role="status"]')],alerts=[...panel.querySelectorAll('[role="alert"]')];need(statuses.length<=1&&alerts.length<=1)
  const classify=(element,kind)=>{
    if(!element)return'ABSENT'
    need(element.classList.contains(kind==='status'?'subscription-notice':'subscription-error'))
    let text
    if(kind==='status'){need(element.tagName==='P'&&element.children.length===0);text=element.textContent.trim()}
    else{const messages=[...element.querySelectorAll('p#subscription-field-error')];need(messages.length===1&&messages[0].children.length===0);text=messages[0].textContent.trim()}
    need(text.length>0&&text.length<=config.maxTextCharacters);const matches=Object.entries(kind==='status'?config.statusTexts:config.alertTexts).filter(([,value])=>value===text);need(matches.length===1);return matches[0][0]
  }
  const visible=element=>Boolean(element&&element.getClientRects().length&&getComputedStyle(element).visibility!=='hidden'&&getComputedStyle(element).display!=='none')
  return{status:classify(statuses[0],'status'),alert:classify(alerts[0],'alert'),statusVisible:visible(statuses[0]),alertVisible:visible(alerts[0])}
}
export function feedbackExpression(domExpression){
  if(typeof domExpression!=='string'||!domExpression.length||domExpression.length>262144)throw Error('handoff feedback rejected')
  const config={statusTexts:C.statusTexts,alertTexts:C.alertTexts,maxTextCharacters:C.maxTextCharacters}
  return`(()=>{const dom=${domExpression};const feedback=(${collectFeedback.toString().replace(/\r\n/g,'\n')})(${JSON.stringify(config)});return{dom,feedback}})()`
}
export class FeedbackObserver{
  constructor(write=raw=>writeSync(2,raw)){if(typeof write!=='function')throw Error('handoff feedback rejected');this.write=write;this.next=0;this.total=0}
  record(row,snapshot){if(row.ordinal!==this.next+1)throw Error('handoff feedback rejected');const value=observationFor(row,snapshot),raw=observationLine(value);if(this.total+raw.length>C.maxProjectionBytes)throw Error('handoff feedback rejected');const count=this.write(raw);if(count!==raw.length)throw Error('handoff feedback rejected');this.next++;this.total+=raw.length;return value}
  complete(){if(this.next!==C.maxRows)throw Error('handoff feedback rejected')}
}
