import {attachVersionInteraction} from './version-interaction.js';
const instances=new WeakMap();
export function disposeVersion(element){instances.get(element)?.controller?.dispose();instances.delete(element);}
import {validSeparator, validPadding, validColor, validSize, validOffset} from './presentation.js';
export function parts(value, scheme) {
  if (scheme !== 'inspr-calendar-v2') return null;
  const match = /^(v?)([1-9][0-9])(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9])(\.0\.0)$/.exec(value);
  if (!match) return null;
  const [, v, yy, mm, dd, hh, mi, ss, tail] = match;
  const date = new Date(Date.UTC(2000 + Number(yy), Number(mm) - 1, Number(dd)));
  if (date.getUTCMonth() + 1 !== Number(mm) || date.getUTCDate() !== Number(dd)) return null;
  return {v, yy, mm, dd, hh, mi, ss, tail};
}
// All presentation styles live in this renderer, also used by portable export.
export function renderVersion(element,value,scheme,{config,mode='reduced',brand='#d69b31',interactive=true}={}) {
  const signature=JSON.stringify([value,scheme,config,mode,brand,interactive]);
  if(instances.get(element)?.signature===signature)return;
  disposeVersion(element);
  element.replaceChildren();element.classList.add('coordinate');
  element.removeAttribute('aria-label');element.removeAttribute('role');
  element.dataset.canonical=String(value).replace(/^v/,'');
  Object.assign(element.style,{fontFamily:'ui-monospace,SFMono-Regular,Menlo,monospace',fontVariantNumeric:'tabular-nums',whiteSpace:'pre',letterSpacing:'0',fontWeight:'inherit'});
  const parsed=parts(value,scheme);
  if(!parsed){element.textContent=value;return;}
  const pretty=mode==='pretty'?config?.pretty:null;
  const tint=config?.tint?.mode==='auto'?brand:config?.tint?.default;
  if(pretty){element.setAttribute('role','img');element.setAttribute('aria-label',value);}
  for(const [key,text] of Object.entries(parsed)) {
    if(!text)continue;
    const digit=document.createElement('span');digit.className=key;digit.textContent=text;
    if(pretty)digit.setAttribute('aria-hidden','true');
    const weight=config?.weights?.[key];
    if(Number.isFinite(weight)&&weight>=0&&weight<=1)digit.style.opacity=String(weight);
    const color=pretty?.colors?.[key];
    if(validColor(color))digit.style.color=color;
    else if(['yy','mm','dd'].includes(key)&&validColor(tint)&&Number.isFinite(config?.tint?.mix))digit.style.color=`color-mix(in oklab,currentColor,${tint} ${Math.max(0,Math.min(1,config.tint.mix))*100}%)`;
    element.append(digit);
    const b=pretty?.separators?.[key];
    if(!b||!validSeparator(b.text))continue;
    const floating=['sup','sub'].includes(b.placement);
    const separator=document.createElement('span');separator.className='separator';separator.setAttribute('aria-hidden','true');separator.dataset.placement=floating?b.placement:'inline';
    // Outer carrier inherits parent font size, so offsets and padding stay in
    // parent em even when only the nested glyph is scaled. Transforms never advance text.
    Object.assign(separator.style,{display:'inline-block',position:'relative',verticalAlign:'baseline',fontSize:'inherit',lineHeight:'inherit',whiteSpace:'pre',transform:`translate(${validOffset(b.offsetX)?b.offsetX:0}em,${validOffset(b.offsetY)?b.offsetY:0}em)`});
    if(floating)Object.assign(separator.style,{width:'0',height:'0',overflow:'visible'});
    separator.style.color=validColor(b.color)?b.color:validColor(brand)?brand:'currentColor';
    const anchor=document.createElement('span');anchor.className='separator-anchor';
    Object.assign(anchor.style,{display:'inline-block',fontSize:'inherit',paddingLeft:`${validPadding(b.paddingLeft)?b.paddingLeft:0}em`,paddingRight:`${validPadding(b.paddingRight)?b.paddingRight:0}em`});
    if(floating)Object.assign(anchor.style,{position:'absolute',left:'0',transform:'translateX(-50%)',whiteSpace:'pre',lineHeight:'1',...(b.placement==='sup'?{bottom:'.65em'}:{top:'.25em'})});
    const glyph=document.createElement('span');glyph.className='separator-glyph';glyph.textContent=b.text;glyph.style.fontSize=`${(validSize(b.size)?b.size:1)*100}%`;
    anchor.append(glyph);separator.append(anchor);element.append(separator);
  }
  if(pretty&&interactive&&typeof element.getBoundingClientRect==='function'){const controller=attachVersionInteraction(element,String(value).replace(/^v/,''));instances.set(element,{signature,controller});}
}
export function portableHTML(value,scheme,options={}) {
  const element=document.createElement('span');renderVersion(element,value,scheme,{...options,interactive:false});
  // Native DOM serialization escapes arbitrary Unicode text and HTML metacharacters.
  for(const child of [element,...element.querySelectorAll('*')])child.removeAttribute('class');
  element.removeAttribute('data-canonical');
  return element.outerHTML;
}
