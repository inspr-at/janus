// Thin product adapter. All typography, timing, animation and copy behavior
// belongs to the verified shared renderer; no mutable runtime configuration.
import {renderVersion} from './vendor/calendar-version/version.js';
import {attachVersionInteraction} from './vendor/calendar-version/version-interaction.js';
const [config, schemes] = await Promise.all(['display.json','schemes.json'].map(async name => {
 const response = await fetch(new URL(`./vendor/calendar-version/${name}`, import.meta.url), {credentials:'same-origin'});
 if (!response.ok) throw new Error('Version presentation unavailable');
 return response.json();
}));
for (const host of document.querySelectorAll('[data-janus-version]')) {
 const coordinate=host.querySelector('[data-coordinate]'), select=host.querySelector('[data-version-format]');
 const value=host.dataset.version, scheme=host.dataset.scheme;
 host.title=`${schemes.labels?.[scheme] || 'INSPR-VER2'} · UTC · Click version to copy`;
 let interaction;
 function render() {
  interaction?.dispose(); interaction=null;
  renderVersion(coordinate,value,scheme,{config,mode:select.value==='pretty'?'pretty':'reduced',brand:'#d69b31'});
  if(select.value==='semver') interaction=attachVersionInteraction(coordinate,value);
 }
 select.addEventListener('change',render); render();
}
