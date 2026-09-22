// INSPR-421 display-only policy. The canonical version grammar is unchanged.
export const segments = ['v','yy','mm','dd','hh','mi','ss','tail'];
export const boundaries = segments.slice(0,-1);
export const separatorDefaults = Object.freeze({text:'',placement:'inline',paddingLeft:0,paddingRight:0,color:'auto',size:1,offsetX:0,offsetY:0});
export const validColor = value => typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value);
const storedColor = value => value === 'auto' || (typeof value === 'string' && /^#[0-9a-f]{6}$/.test(value));
export const validSeparator = value => typeof value === 'string' && [...value].length <= 32 && !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value);
const hundredth = (value,min,max) => Number.isFinite(value) && value >= min && value <= max && Math.abs(value*100-Math.round(value*100)) <= 1e-9;
export const validPadding = value => hundredth(value,0,2);
export const validOffset = value => hundredth(value,-2,2);
export const validSize = value => hundredth(value,.1,3);
export function normalizeConfig(input) {
  const config=structuredClone(input);
  config.schema='inspr.calendar-version-display.v2';
  config.floor={...config.floor,yy:0};
  config.tint={...config.tint,mode:config.tint?.mode === 'custom'?'custom':'auto'};
  const color = value => typeof value==='string'?value.toLowerCase():value;
  config.pretty={
    separators:Object.fromEntries(boundaries.map(key=>[key,Object.fromEntries(Object.entries(separatorDefaults).map(([field,fallback])=>[field,field==='color'?color(config.pretty?.separators?.[key]?.[field]??fallback):config.pretty?.separators?.[key]?.[field]??fallback]))])),
    colors:Object.fromEntries(segments.map(key=>[key,color(config.pretty?.colors?.[key]??'auto')])),
  };
  return config;
}
export function validPresentation(config) {
  return config?.schema==='inspr.calendar-version-display.v2' && config.scheme==='inspr-calendar-v2'
    && segments.every(key=>Number.isFinite(config.weights?.[key])&&config.weights[key]>=0&&config.weights[key]<=1)
    && ['auto','custom'].includes(config.tint?.mode) && /^#[0-9a-f]{6}$/.test(config.tint.default)
    && Number.isFinite(config.tint.mix)&&config.tint.mix>=0&&config.tint.mix<=1
    && boundaries.every(key=>{
      const b=config.pretty?.separators?.[key];
      return b && Object.keys(b).length===8 && Object.keys(separatorDefaults).every(k=>Object.hasOwn(b,k))
        && validSeparator(b.text)&&['inline','sup','sub'].includes(b.placement)
        && validPadding(b.paddingLeft)&&validPadding(b.paddingRight)&&storedColor(b.color)
        && validSize(b.size)&&validOffset(b.offsetX)&&validOffset(b.offsetY);
    }) && segments.every(key=>storedColor(config.pretty?.colors?.[key]));
}
