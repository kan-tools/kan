const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');
function theme({dark=false,saved=null,blocked=false}={}){
 const events={},control={events:{},addEventListener(k,f){this.events[k]=f;}};
 const media={matches:dark,addEventListener(k,f){this.change=f;}};
 const stored=new Map(saved===null?[]:[['kan.theme',saved]]);
 const context={window:{matchMedia:q=>{assert.equal(q,'(prefers-color-scheme: dark)');return media;},addEventListener:(k,f)=>events[k]=f},document:{documentElement:{dataset:{}},getElementById:()=>control,addEventListener:(k,f)=>events[k]=f},localStorage:{getItem:k=>{if(blocked)throw Error('disabled');return stored.get(k);},setItem:(k,v)=>{if(blocked)throw Error('disabled');stored.set(k,v);},removeItem:k=>{if(blocked)throw Error('disabled');stored.delete(k);}}};
 vm.runInNewContext(fs.readFileSync('web/theme.js','utf8'),context);
 const current=()=>context.document.documentElement.dataset.theme;
 const initial=current();events.DOMContentLoaded();
 return{current,initial,control,stored,platform:dark=>{media.matches=dark;media.change();},select:v=>{control.value=v;control.events.change();},storage:events.storage};
}
test('first paint defaults to platform; System follows live platform changes',()=>{for(const dark of [false,true]){const t=theme({dark});assert.equal(t.initial,dark?'dark':'light');assert.equal(t.control.value,'system');t.platform(!dark);assert.equal(t.current(),dark?'light':'dark');assert.equal(t.stored.size,0);}});
test('explicit choice persists only the theme and overrides platform until System selected',()=>{const t=theme({dark:true});t.select('light');t.platform(true);assert.equal(t.current(),'light');assert.deepEqual([...t.stored],[['kan.theme','light']]);assert.equal(theme({dark:true,saved:'light'}).initial,'light');t.select('dark');t.platform(false);assert.equal(t.current(),'dark');t.select('system');assert.equal(t.current(),'light');assert.equal(t.stored.size,0);});
test('invalid preference, unavailable storage and cross-tab updates degrade safely',()=>{assert.equal(theme({dark:true,saved:'garbage'}).initial,'dark');const t=theme({blocked:true});t.select('dark');assert.equal(t.current(),'dark');t.storage({key:'unrelated',newValue:'light'});assert.equal(t.current(),'dark');t.storage({key:'kan.theme',newValue:'light'});assert.equal(t.current(),'light');t.storage({key:null,newValue:null});assert.equal(t.control.value,'system');});
test('production and preview load the same theme controller before content',()=>{for(const path of ['web/operations/index.html','.design/kan-studio/index.html']){const html=fs.readFileSync(path,'utf8');assert.ok(html.indexOf('theme.js')<html.indexOf('<body>'));assert.match(html,/id="theme"/);}assert.equal(fs.readFileSync('.design/kan-studio/theme.js','utf8'),fs.readFileSync('web/theme.js','utf8'));});
