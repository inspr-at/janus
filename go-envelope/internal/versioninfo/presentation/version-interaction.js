import autoAnimate from './auto-animate.js';
import './auto-animate-license.js';
export const hoverOpacity = weight => .70+.30*(Number.isFinite(weight)?Math.max(0,Math.min(1,weight)):1);
const duration=1000;

// AutoAnimate owns FLIP scheduling, Animation playback/cancellation and observers.
// Its documented plugin receives the new layout. Snapshot current visual bounds
// before a mutation so interruption starts here, not at its cached old target.
export function attachVersionInteraction(host,canonical,{animate=autoAnimate,view=globalThis}={}) {
  const doc=host.ownerDocument||document,originalStyle=host.getAttribute('style'),originalWidth=host.style.width;
  const attributes=Object.fromEntries(['role','tabindex','aria-label'].map(name=>[name,host.getAttribute(name)]));
  const sequence=doc.createElement('span');sequence.style.display='inline-block';sequence.style.position='relative';
  const nodes=[...host.children],carriers=nodes.map(node=>{
    const carrier=doc.createElement('span');Object.assign(carrier.style,{display:'inline-block',position:'relative',verticalAlign:'baseline'});
    carrier.append(node);sequence.append(carrier);return {carrier,node,separator:node.className==='separator',opacity:node.style.opacity||'1',color:node.style.color||'',transition:node.style.transition||'',userSelect:node.style.userSelect||''};
  });host.append(sequence);
  host.setAttribute('role','button');host.setAttribute('tabindex','0');host.setAttribute('aria-label',`${canonical} — Version kopieren`);
  Object.assign(host.style,{display:'inline-block',position:'relative',cursor:'pointer',userSelect:'text',outlineOffset:'4px'});
  const feedback=doc.createElement('span');feedback.setAttribute('role','status');feedback.setAttribute('aria-live','polite');
  Object.assign(feedback.style,{position:'absolute',bottom:'100%',left:'0',fontFamily:'system-ui,sans-serif',fontSize:'12px',fontWeight:'400',lineHeight:'1.5',whiteSpace:'normal',padding:'3px 7px',borderRadius:'4px',background:'#17304a',color:'#fff',pointerEvents:'none',zIndex:'2'});
  feedback.hidden=true;host.append(feedback);
  let hovered=false,focused=false,down=false,dragged=false,technical=false,disposed=false,controller=null,timer=null,copySerial=0,start=null;
  let snapshots=new Map();const listeners=[];
  const media=view.matchMedia?.('(prefers-reduced-motion: reduce)');
  const reduced=()=>media?.matches===true;
  const listen=(target,type,fn)=>{target.addEventListener(type,fn);listeners.push(()=>target.removeEventListener(type,fn));};
  const selected=()=>{const s=doc.getSelection?.();return Boolean(s&&!s.isCollapsed&&(host.contains(s.anchorNode)||host.contains(s.focusNode)));};
  function plugin(el,_action,oldRect,newRect){
    const previous=snapshots.get(el)||oldRect,current=el.getBoundingClientRect?.()||newRect||oldRect;
    // Children include the parent's alignment shift in their viewport snapshots.
    // Do not animate that same shift a second time on the sequence itself.
    const dx=el!==sequence&&previous&&current?previous.left-current.left:0,dy=el!==sequence&&previous&&current?previous.top-current.top:0;
    return new view.KeyframeEffect(el,[{transform:`translate(${dx}px, ${dy}px)`},{transform:'translate(0, 0)'}],{duration:reduced()?0:duration,easing:'ease-in-out'});
  }
  function motion(target,immediate=false){
    if(disposed)return;
    if(target===technical){if(immediate)finish();return;}
    if(!host.style.width){const width=host.getBoundingClientRect?.().width;if(width)host.style.width=`${width}px`;}
    snapshots=new Map([sequence,...carriers.map(c=>c.carrier)].map(el=>[el,el.getBoundingClientRect?.()]));
    if(!controller&&!reduced()&&view.KeyframeEffect&&view.ResizeObserver)controller=animate(sequence,plugin);
    if(immediate||reduced())controller?.disable();else controller?.enable();
    technical=target;host.dataset.versionView=target?'technical':'pretty';
    const origin=snapshots.get(sequence);
    for(const item of carriers){
      const {carrier,node,separator}=item;
      node.style.transition=(reduced()||immediate)?'none':`opacity ${duration}ms ease-in-out, color ${duration}ms ease-in-out`;
      if(separator){
        node.style.userSelect='none';node.style.opacity=target?'0':'1';
        if(target){const rect=snapshots.get(carrier);Object.assign(carrier.style,{position:'absolute',left:`${rect&&origin?rect.left-origin.left:0}px`,top:`${rect&&origin?rect.top-origin.top:0}px`});}
        else Object.assign(carrier.style,{position:'relative',left:'',top:''});
      }else {node.style.opacity=target?String(hoverOpacity(Number(item.opacity))):item.opacity;node.style.color=target?'currentColor':item.color;}
    }
    // Move the SAME last digit carrier to trigger childList without disposable
    // placeholders. All nodes remain connected; AutoAnimate runs remain only.
    if(carriers.length)sequence.append(carriers.at(-1).carrier);
  }
  function finish(){for(const el of [sequence,...carriers.flatMap(c=>[c.carrier,c.node])]){for(const animation of el.getAnimations?.()||[])try{animation.finish();}catch{} }if(reduced()||selected())for(const {node} of carriers)node.style.transition='none';}
  const settle=()=>motion(hovered||focused||down||selected(),selected());
  listen(host,'pointerenter',e=>{hovered=e.pointerType!=='touch';settle();});listen(host,'pointerleave',()=>{hovered=false;settle();});
  listen(host,'focus',()=>{focused=!down;host.style.outline='2px solid currentColor';settle();});
  listen(host,'blur',()=>{focused=false;host.style.outline='';settle();});
  listen(host,'pointerdown',e=>{down=true;dragged=false;start={x:e.clientX,y:e.clientY};motion(true);});
  listen(host,'pointermove',e=>{if(down&&start&&Math.hypot(e.clientX-start.x,e.clientY-start.y)>4){dragged=true;motion(true,true);}});
  listen(doc,'pointerup',()=>{down=false;settle();});listen(doc,'pointercancel',()=>{down=false;dragged=true;settle();});
  listen(doc,'selectionchange',settle);
  async function copy(){
    if(disposed||selected()||dragged)return;
    const serial=++copySerial;view.clearTimeout(timer);feedback.hidden=true;feedback.textContent='';host.dataset.copyState='copying';
    try{await view.navigator.clipboard.writeText(canonical);if(disposed||serial!==copySerial)return;host.dataset.copyState='copied';feedback.textContent='Kopiert';}
    catch{if(disposed||serial!==copySerial)return;host.dataset.copyState='error';feedback.textContent='Kopieren nicht verfügbar. Version markieren.';}
    feedback.hidden=false;timer=view.setTimeout(()=>{feedback.hidden=true;feedback.textContent='';delete host.dataset.copyState;},1800);
  }
  listen(host,'click',()=>{void copy();});listen(host,'keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();if(!e.repeat){dragged=false;void copy();}}});
  const preference=()=>{if(reduced())finish();settle();};if(media?.addEventListener)listen(media,'change',preference);
  host.dataset.versionView='pretty';
  return {dispose(){
    if(disposed)return;disposed=true;++copySerial;view.clearTimeout(timer);listeners.forEach(remove=>remove());controller?.destroy?.();
    for(const item of carriers)Object.assign(item.node.style,{opacity:item.opacity,color:item.color,transition:item.transition,userSelect:item.userSelect});
    feedback.remove();host.replaceChildren(...nodes);host.style.width=originalWidth;
    for(const [name,value] of Object.entries(attributes))if(value===null)host.removeAttribute(name);else host.setAttribute(name,value);
    if(originalStyle===null)host.removeAttribute('style');else host.setAttribute('style',originalStyle);
    delete host.dataset.versionView;delete host.dataset.copyState;
  },technical:()=>technical};
}
