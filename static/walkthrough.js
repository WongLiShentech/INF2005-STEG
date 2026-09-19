'use strict';
const $=id=>document.getElementById(id),names=['Cover','Payload','Protect','Transfer','Receive','Verdict'];
let activeStage=1;
let stage=1,kind='image',mode='text',selectedSample='',samples=[],run=null,previewURL=null,attempt=0;
const historyKey='steg-analysis-runs-v2';
let runs=[];
try{const saved=JSON.parse(sessionStorage.getItem(historyKey)||'[]');if(Array.isArray(saved))runs=saved.filter(r=>r&&typeof r.id==='string'&&typeof r.cover==='string'&&r.cover.startsWith('/media/')&&typeof r.output==='string'&&r.output.startsWith('/media/'));}catch{}
function showTab(name){const demo=name==='demo';$('demo-panel').hidden=!demo;$('analysis-panel').hidden=demo;for(const id of ['demo','analysis']){const selected=(id===name);$(id+'-tab').setAttribute('aria-selected',String(selected));$(id+'-tab').tabIndex=selected?0:-1;}document.querySelectorAll('audio,video').forEach(el=>el.pause());}
$('demo-tab').onclick=$('back-demo').onclick=()=>showTab('demo');
$('analysis-tab').onclick=$('view-analysis').onclick=()=>showTab('analysis');
for(const id of ['demo','analysis'])$(id+'-tab').onkeydown=e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();const next=e.key==='Home'?'demo':e.key==='End'?'analysis':id==='demo'?'analysis':'demo';showTab(next);$(next+'-tab').focus();}};
function progress(){document.querySelector('.progress').innerHTML=names.map((n,i)=>'<button data-stage="'+(i+1)+'" '+(i+1>stage?'disabled':'')+' '+(i+1===activeStage?'aria-current="step"':'')+' class="'+(i+1===activeStage?'active':i+1<stage?'done':'')+'"><span>'+(i+1)+'</span> '+n+'</button>').join('')}
function advance(n){stage=Math.max(stage,n);activeStage=n;for(let i=1;i<=6;i++)$('s'+i).hidden=i!==n;progress();showTab('demo');document.querySelector('#s'+n+' .stage-head h2').setAttribute('tabindex','-1');document.querySelector('#s'+n+' .stage-head h2').focus({preventScroll:true});$('s'+n).scrollTop=0;}
document.querySelector('.progress').onclick=e=>{const button=e.target.closest('[data-stage]');if(button&&!button.disabled)advance(Number(button.dataset.stage));};
function renderHistory(){
 $('clear-history').disabled=runs.length===0;$('run-count').textContent=runs.length;$('analysis-empty').hidden=runs.length>0;$('analysis-runs').replaceChildren();
 runs.forEach((d,i)=>{
  const card=document.createElement('article');card.className='analysis-run';
  const heading=document.createElement('h3');heading.textContent='Run '+(i+1)+' / '+d.kind+' / '+d.depth+' LSB';
  const detail=document.createElement('p');detail.className='muted';detail.textContent=d.input_bytes+' B payload / '+d.used_bytes+' B embedded / '+(d.encrypted?'AES-256-GCM':'Encryption off');
  const compare=document.createElement('div');compare.className='compare';
  compare.append(imageOrAudio(d.cover_preview||d.cover,d.kind,'Original cover'),imageOrAudio(d.output_preview||d.output,d.kind,'Stego object'));
  if(d.kind==='image')compare.querySelectorAll('img').forEach(img=>{const a=document.createElement('a');a.href=img.src;a.target='_blank';a.rel='noopener';a.title='Open full-resolution image';img.replaceWith(a);a.append(img);});
  const metrics=document.createElement('div');metrics.className='metrics';
  for(const [label,value] of [['PSNR',d.psnr===null?'Infinite':d.psnr+' dB'],['Values changed',d.changed.toLocaleString()+' / '+d.changed_percent.toFixed(3)+'%'],['Largest value change',d.max_change]]){const box=document.createElement('div');box.className='metric';const name=document.createElement('small'),number=document.createElement('strong');name.textContent=label;number.textContent=value;box.append(name,number);metrics.append(box);}
  card.append(heading,detail,compare,metrics);$('analysis-runs').append(card);attachCharts(card,d.id);
 });
}
function rememberRun(d){if(runs.some(r=>r.id===d.id))return;const saved={};for(const key of ['id','kind','depth','cover','output','cover_preview','output_preview','input_bytes','used_bytes','encrypted','psnr','changed','changed_percent','max_change'])saved[key]=d[key];runs.push(saved);try{sessionStorage.setItem(historyKey,JSON.stringify(runs));}catch{$('history-warning').textContent='Browser storage unavailable. Run history will be lost on refresh.';}renderHistory();}
renderHistory();
$('clear-history').onclick=()=>{try{sessionStorage.removeItem(historyKey);}catch{$('history-warning').textContent='Unable to clear browser storage. Please enable browser storage and try again.';return;}document.querySelectorAll('#analysis-runs audio,#analysis-runs video').forEach(el=>el.pause());runs=[];$('history-warning').textContent='';renderHistory();};
async function post(route,data){const response=await fetch(route,{method:'POST',body:data});let value;try{value=await response.json()}catch{throw Error('Unexpected server response. Reload the page and try again.')}if(!response.ok||value.error)throw Error(value.error||'Request failed');return value}
function inputBytes(){return mode==='file'?$('payload-file').files[0]?.size||0:new TextEncoder().encode($('message').value).length}
function coverForm(){const data=new FormData(),file=$('cover-file').files[0];if(file)data.set('file',file);else data.set('sample',selectedSample);data.set('key',$('sender-pass').value);data.set('lsb_n',$('depth').value);data.set('offset',$('offset').value);return data}
function imageOrAudio(url,type,caption){const figure=document.createElement('figure'),tag=type==='audio'?'audio':type==='video'?'video':'img',element=document.createElement(tag);element.src=url;element.className='art';if(type==='audio'||type==='video')element.controls=true;else element.alt=caption;const label=document.createElement('figcaption');label.textContent=caption;figure.append(element,label);return figure}
function kindOfName(name){const n=name.toLowerCase();if(n.endsWith('.wav'))return'audio';if(/\.(avi|mp4|mov|mkv)$/.test(n))return'video';return'image'}
function renderCovers(){const visible=samples.filter(s=>s.kind===kind);if(!visible.some(s=>s.name===selectedSample))selectedSample=(visible.find(s=>s.default)||visible[0])?.name||'';$('covers').replaceChildren();for(const sample of visible){const button=document.createElement('button');button.className='cover-card'+(sample.name===selectedSample&&!$('cover-file').files[0]?' selected':'');button.setAttribute('aria-pressed',sample.name===selectedSample&&!$('cover-file').files[0]?'true':'false');if(kind==='image'){const img=document.createElement('img');img.src='/sample/'+encodeURIComponent(sample.name);img.alt=sample.name;img.className='art';button.append(img)}else{const art=document.createElement('div');art.className='art';art.style.cssText='display:grid;place-items:center;color:#126855;font-weight:700';art.textContent=sample.label+' / '+(kind==='video'?'AVI':'WAV');button.append(art)}const cap=document.createElement('span');cap.className='caption';const title=document.createElement('strong'),detail=document.createElement('small');title.textContent=sample.label||sample.name;detail.textContent=sample.description;cap.append(title,detail);button.append(cap);button.onclick=()=>{selectedSample=sample.name;$('cover-file').value='';renderCovers();renderPreview()};$('covers').append(button)}updateSummary()}
function renderPreview(){if(previewURL){URL.revokeObjectURL(previewURL);previewURL=null}const file=$('cover-file').files[0];const name=file?.name||selectedSample;if(!name)return;kind=kindOfName(name);const url=file?(previewURL=URL.createObjectURL(file)):'/sample/'+encodeURIComponent(name);$('local-preview').replaceChildren(imageOrAudio(url,kind,name));$('cover-detail').textContent=file?file.size.toLocaleString()+' bytes':samples.find(s=>s.name===name)?.description||'';invalidateCapacity();updateSummary()}
function updateSummary(){$('sum-cover').textContent=$('cover-file').files[0]?.name||selectedSample;$('sum-payload').textContent=mode==='file'?$('payload-file').files[0]?.name||'Choose a file':inputBytes()+' B text';$('sum-depth').textContent=$('depth').value+' LSB';$('depth-label').textContent=$('depth').value}
let capacityRequest=0,capacityTimer=null,capacityReady=false,lastCapacity=null;
function invalidateCapacity(){
 clearTimeout(capacityTimer);capacityRequest++;capacityReady=false;$('protect').disabled=true;$('inspect').disabled=false;
 $('payload-error').textContent='';$('capacity-bar').style.width='0';updateSummary();
 const file=$('payload-file').files[0];$('payload-file-info').textContent=file?file.size.toLocaleString()+' B selected':'Select a file to check its size automatically.';
 $('capacity').textContent='Capacity check required';$('capacity-detail').textContent='Enter your payload and passphrase to check automatically.';
 if(run)return;
 if(inputBytes()&&lastCapacity&&lastCapacity.key===capacityKey()&&inputBytes()>lastCapacity.bytes)$('payload-error').textContent='Payload too large for this cover. Choose a smaller payload, a larger cover, or increase LSB depth.';
 if(!inputBytes())return;
 $('capacity-detail').textContent='Checking complete payload size?';capacityTimer=setTimeout(checkCapacity,250);
}
function capacityKey(){return [selectedSample,$('cover-file').files[0]?.name,$('sender-pass').value,$('offset').value,$('depth').value].join('|')}
async function checkCapacity(){
 clearTimeout(capacityTimer);const requestId=++capacityRequest;capacityReady=false;$('protect').disabled=true;$('inspect').disabled=true;
 const data=coverForm(),key=capacityKey();data.set('payload_size',inputBytes());data.set('payload_name',mode==='file'?$('payload-file').files[0]?.name||'':'message.txt');if($('encrypt').checked)data.set('encrypt','on');
 try{const d=await post('/api/capacity',data);if(requestId!==capacityRequest)return;
 const capacity=d.capacity[$('depth').value];lastCapacity={key,bytes:capacity};
 $('capacity').textContent=d.upper_bound?'Maximum body capacity: '+capacity.toLocaleString()+' B\nStart index: requires passphrase':'Body capacity: '+capacity.toLocaleString()+' B\nEmbedding start index: '+d.offset.toLocaleString();
 $('capacity-detail').textContent=d.required_bytes.toLocaleString()+' B required (message + record + signature).';
 $('capacity-bar').style.width=Math.min(100,d.required_bytes/Math.max(1,capacity)*100)+'%';$('capacity-bar').classList.toggle('over-capacity',!d.fits);
 capacityReady=d.fits&&!!$('sender-pass').value.trim()&&inputBytes()>0&&(mode==='file'||$('message').value.trim().length>0);
 $('payload-error').textContent=d.fits?'':'Payload too large: '+d.required_bytes.toLocaleString()+' B required; '+capacity.toLocaleString()+' B '+(d.upper_bound?'maximum available':'available')+'. Choose a smaller payload, a larger cover, or increase LSB depth.';
 if(d.fits&&!$('sender-pass').value.trim())$('capacity-detail').textContent+=' Enter a passphrase to confirm the final fit.';
 $('protect').disabled=!capacityReady;
 }catch(e){if(requestId===capacityRequest)$('payload-error').textContent=e.message;}finally{if(requestId===capacityRequest)$('inspect').disabled=false;}
}
$('media-tabs').onclick=e=>{const button=e.target.closest('[data-kind]');if(!button||stage>1)return;kind=button.dataset.kind;$('cover-file').value='';$('video-note').hidden=kind!=='video';document.querySelectorAll('[data-kind]').forEach(b=>{b.classList.toggle('selected',b===button);b.setAttribute('aria-pressed',b===button?'true':'false')});renderCovers();renderPreview()};
$('cover-file').onchange=()=>{const file=$('cover-file').files[0];if(file&&!/\.(png|bmp|jpe?g|wav|avi|mp4|mov|mkv)$/i.test(file.name)){$('cover-error').textContent='Choose PNG, BMP, JPEG, WAV or a video (AVI/MP4/MOV/MKV).';$('cover-file').value='';return}$('cover-error').textContent='';renderPreview();renderCovers()};
$('choose-cover').onclick=()=>{if(!selectedSample&&!$('cover-file').files[0])return;document.querySelectorAll('#s1 button,#s1 input').forEach(el=>el.disabled=true);advance(2)};
$('payload-tabs').onclick=e=>{const b=e.target.closest('[data-mode]');if(!b||run)return;mode=b.dataset.mode;document.querySelectorAll('[data-mode]').forEach(x=>x.classList.toggle('selected',x===b));$('text-label').hidden=mode!=='text';$('file-label').hidden=mode!=='file';invalidateCapacity();};
for(const id of ['message','payload-file'])$(id).addEventListener('input',invalidateCapacity);for(const id of ['sender-pass','depth','offset','encrypt'])$(id).addEventListener('input',invalidateCapacity);
$('payload-file').addEventListener('change',invalidateCapacity);
$('inspect').onclick=checkCapacity;
function facts(target,rows){target.replaceChildren();for(const [name,value]of rows){const div=document.createElement('div'),dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;dd.className='hash';div.append(dt,dd);target.append(div)}}
function bits(value,width,depth){const binary=value.toString(2).padStart(width,'0');return binary.slice(0,-depth)+'<mark>'+binary.slice(-depth)+'</mark>'}
function trail(target,rows){target.replaceChildren();for(const c of rows){const li=document.createElement('li'),mark=document.createElement('b'),body=document.createElement('div'),title=document.createElement('strong'),detail=document.createElement('small');mark.textContent=c.ok?'PASS':'FAIL';if(!c.ok)mark.style.color='#a03b24';title.textContent=c.label;detail.textContent=c.detail;body.append(title,detail);if(c.compared?.length){const pre=document.createElement('pre');pre.className='hash';pre.textContent=c.compared.map(([k,v])=>k+': '+v).join('\n');const more=document.createElement('details'),summary=document.createElement('summary');summary.textContent='Compare SHA-256 values';more.open=!c.ok;more.append(summary,pre);body.append(more)}li.append(mark,body);target.append(li)}}
function renderProtection(d){$('run-config').textContent=d.kind+' / '+d.depth+' LSB / '+(d.encrypted?'AES-256-GCM':'plaintext')+' / offset '+d.offset;$('stored-count').textContent=d.used_bytes.toLocaleString()+' / '+d.capacity.toLocaleString()+' bytes (record + signature + stored message)';$('message-size-summary').textContent=d.input_bytes+' B input / '+d.stored_bytes+' B stored'+(d.encrypted?' (includes 28 B encryption overhead)':'');$('protection-status').textContent=(d.encrypted?'AES-256-GCM encrypted':'Encryption off')+' / RSA-PSS record signed / Embedding saved';$('signed-json').textContent=d.record_json;$('regions').textContent=Object.entries(d.regions).map(([label,[a,b]])=>({'header':'Header','record_signature':'Record + signature','message':'Message'}[label]||label)+': '+a+' - '+b).join('\n');$('bit-rows').innerHTML=d.rows.filter((r,i)=>r.region==='Message'||i===0).map(r=>'<tr><td>'+r.region+' / '+r.index+'</td><td>'+r.depth+'</td><td class="hash">'+bits(r.before,r.width,r.depth)+'</td><td class="hash">'+bits(r.after,r.width,r.depth)+'</td></tr>').join('');$('output-name').textContent=d.output.split('/').pop();$('transfer-name').textContent=$('output-name').textContent;$('download').href=d.output;$('receiver-offset-label').hidden=$('offset').value==='';$('scenario').querySelector('[value="tampered"]').disabled=d.depth>=d.rows[0].width;if(d.depth>=d.rows[0].width)$('output-name').textContent+=' / Full depth: masked media hash has no remaining content bits.'}
$('protect').onclick=async()=>{if(!capacityReady||run)return;$('payload-error').textContent='';if(!inputBytes()){$('payload-error').textContent='Enter a message or select a payload file.';return}const data=coverForm();if($('encrypt').checked)data.set('encrypt','on');if(mode==='file')data.set('message_file',$('payload-file').files[0]);else data.set('message',$('message').value);$('protect').disabled=true;$('protect').textContent='Protecting...';$('payload-fields').disabled=true;try{run=await post('/api/protect',data);renderProtection(run);rememberRun(run);$('protect').textContent='Protected';advance(3)}catch(e){$('payload-error').textContent=e.message;$('payload-fields').disabled=false;capacityReady=false;$('protect').disabled=true;$('protect').textContent='Protect'}};
$('to-transfer').onclick=()=>advance(4);$('to-receive').onclick=()=>advance(5);
$('verify').onclick=async()=>{$('receive-error').textContent='';$('verify').disabled=true;$('verify').textContent='Verifying...';const form=new FormData();form.set('id',run.id);form.set('key',$('receiver-pass').value);form.set('offset',$('receiver-offset').value);form.set('public_key_name',$('public-key').value);form.set('scenario',$('scenario').value);try{const d=await post('/api/verify',form);$('verdict').replaceChildren();const title=document.createElement('h3'),p=document.createElement('p');title.textContent=d.verdict;p.textContent=d.explanation;$('verdict').append(title,p);$('verdict').className='verdict'+(d.verdict==='Authentic'?'':' bad');trail($('verify-trail'),d.checks);const failed=d.checks.find(c=>!c.ok),row=document.createElement('tr');for(const value of [++attempt,$('scenario').selectedOptions[0].textContent+' / '+d.key,failed?.label||'None',d.verdict]){const cell=document.createElement('td');cell.textContent=value;row.append(cell)}$('attempts').append(row);$('recovered').hidden=!d.payload_url;$('payload-preview').replaceChildren();if(d.payload_url){if(d.payload_type==='text/plain')$('payload-preview').textContent=d.message_text;else if(d.payload_type.startsWith('image/')||d.payload_type.startsWith('audio/')||d.payload_type.startsWith('video/'))$('payload-preview').append(imageOrAudio(d.payload_url,d.payload_type.startsWith('audio/')?'audio':d.payload_type.startsWith('video/')?'video':'image','Recovered payload'));else{const a=document.createElement('a');a.href=d.payload_url;a.textContent='Download recovered payload';$('payload-preview').append(a)}}$('record-json').textContent='Public key SHA-256: '+d.public_fingerprint+'\n\n'+JSON.stringify(d.record,null,2);advance(6)}catch(e){$('receive-error').textContent=e.message}finally{$('verify').disabled=false;$('verify').textContent='Verify'}};
$('retry').onclick=()=>{advance(5);$('receiver-pass').focus()};$('restart').onclick=$('reset-top').onclick=()=>location.reload();
(async()=>{try{const response=await fetch('/api/options');if(!response.ok)throw Error('Demo server unavailable');const data=await response.json();samples=data.samples;$('public-key').replaceChildren();for(const name of data.keys){const option=document.createElement('option');option.value=name;option.textContent=name;$('public-key').append(option)}$('public-key').value='demo_public.pem';renderCovers();renderPreview();progress();}catch(e){$('connection-error').textContent='Unable to connect to the application. Reload the page or restart Flask.';$('choose-cover').disabled=true}})();

/* --- Steganalysis charts -------------------------------------------------
   Audio hides a payload too well to hear, so the analysis panel has to make
   the difference visible instead. Two charts, drawn as inline SVG from
   arrays the server already reduced to a few hundred points: no library, no
   canvas, and nothing that needs the network.

   The waveform is styled as a patient monitor on purpose. A static picture
   of a sound is hard to connect to the sound itself; a trace that lights up
   under a moving head, in time with what is playing, is not. */

const CHART = {
  w: 1000, h: 150, pad: 10,
  ink: '#08120e', grid: 'rgba(120,220,175,0.10)', axis: 'rgba(120,220,175,0.28)',
  cover: '#3ef2a0', stego: '#ffb454', dim: 0.3,
};

let chartSeq = 0;

function shape(name, attrs) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', name);
  for (const key in attrs) node.setAttribute(key, attrs[key]);
  return node;
}

function svg(height) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  node.setAttribute('viewBox', '0 0 ' + CHART.w + ' ' + (height || CHART.h));
  node.setAttribute('preserveAspectRatio', 'none');
  node.setAttribute('class', 'chart');
  node.setAttribute('role', 'img');
  node.append(shape('rect', {width: CHART.w, height: height || CHART.h, fill: CHART.ink}));
  return node;
}

/* The ruled paper an ECG trace is read against. Decorative, but it gives the
   eye something to measure movement against, which a bare trace does not. */
function grid(node, height) {
  const tall = height || CHART.h;
  for (let x = 0; x <= CHART.w; x += 40) {
    node.append(shape('line', {x1: x, y1: 0, x2: x, y2: tall, stroke: CHART.grid, 'stroke-width': 1}));
  }
  for (let y = 0; y <= tall; y += 25) {
    node.append(shape('line', {x1: 0, y1: y, x2: CHART.w, y2: y, stroke: CHART.grid, 'stroke-width': 1}));
  }
}

/* Where the payload actually sits, so a reader can see the changed span
   against the part of the file nothing touched. */
function shadeRegion(node, region, height) {
  if (!region) return;
  const tall = height || CHART.h;
  const x = region[0] * CHART.w, width = Math.max(1, (region[1] - region[0]) * CHART.w);
  node.append(shape('rect', {x: x, y: 0, width: width, height: tall,
                             fill: '#ffffff', 'fill-opacity': 0.06}));
  // Edges as well as fill: a wash this faint is easy to miss on a dark
  // panel, and the boundaries are the part worth seeing.
  for (const edge of [x, x + width]) {
    node.append(shape('line', {x1: edge, y1: 0, x2: edge, y2: tall,
                               stroke: 'rgba(255,255,255,0.35)', 'stroke-width': 1,
                               'stroke-dasharray': '3 3'}));
  }
}

function glowFilter(node, id, colour) {
  const filter = shape('filter', {id: id, x: '-50%', y: '-50%', width: '200%', height: '200%'});
  filter.append(shape('feDropShadow', {dx: 0, dy: 0, stdDeviation: 3,
                                       'flood-color': colour, 'flood-opacity': 0.9}));
  const defs = shape('defs', {});
  defs.append(filter);
  node.append(defs);
}

/* The trace is drawn twice: once dim across the whole width, once bright and
   clipped to everything already played. The clip advances with the audio, so
   the bright part is exactly what has been heard. */
function waveformChart(series, region, colour) {
  const id = 'wave' + (chartSeq += 1);
  const node = svg();
  grid(node);
  shadeRegion(node, region);

  const mid = CHART.h / 2, scale = (CHART.h / 2) - CHART.pad;
  const top = series.high.map((v, i) => (i * CHART.w / (series.high.length - 1)) + ',' + (mid - v * scale));
  const bottom = series.low.map((v, i) => (i * CHART.w / (series.low.length - 1)) + ',' + (mid - v * scale)).reverse();
  const points = top.concat(bottom).join(' ');

  glowFilter(node, id + 'glow', colour);
  const clip = shape('clipPath', {id: id + 'clip'});
  const window = shape('rect', {x: 0, y: 0, width: 0, height: CHART.h});
  clip.append(window);
  node.querySelector('defs').append(clip);

  node.append(shape('line', {x1: 0, y1: mid, x2: CHART.w, y2: mid,
                             stroke: CHART.axis, 'stroke-width': 1}));
  node.append(shape('polygon', {points: points, fill: colour, 'fill-opacity': CHART.dim}));

  const lit = shape('g', {'clip-path': 'url(#' + id + 'clip)', filter: 'url(#' + id + 'glow)'});
  lit.append(shape('polygon', {points: points, fill: colour, 'fill-opacity': 0.95}));
  node.append(lit);

  const head = shape('line', {x1: 0, y1: 0, x2: 0, y2: CHART.h, stroke: '#ffffff',
                              'stroke-width': 2, 'vector-effect': 'non-scaling-stroke',
                              filter: 'url(#' + id + 'glow)', opacity: 0, class: 'playhead'});
  node.append(head);
  node.classList.add('seekable');
  node.lit = window;
  return node;
}

/* Position is read from the player on every update rather than animated on a
   timer, so the trace cannot drift out of step with what is being heard. */
function followPlayback(chart, media) {
  if (!media || !chart.lit) return;
  const head = chart.querySelector('.playhead');
  const place = () => {
    if (!media.duration || !isFinite(media.duration)) return;
    const fraction = Math.min(1, media.currentTime / media.duration);
    const x = fraction * CHART.w;
    chart.lit.setAttribute('width', x);
    head.setAttribute('x1', x);
    head.setAttribute('x2', x);
    head.setAttribute('opacity', fraction > 0 ? 1 : 0);
  };
  const reset = () => {
    chart.lit.setAttribute('width', 0);
    head.setAttribute('opacity', 0);
  };
  for (const event of ['timeupdate', 'seeked', 'loadedmetadata', 'play']) {
    media.addEventListener(event, place);
  }
  media.addEventListener('ended', reset);
  chart.addEventListener('click', event => {
    if (!media.duration || !isFinite(media.duration)) return;
    const box = chart.getBoundingClientRect();
    media.currentTime = ((event.clientX - box.left) / box.width) * media.duration;
    place();
  });
  place();
}

/* Bars, not a line: the difference is zero almost everywhere, and a line
   drawn through zeros reads as "no data" rather than "no change". */
function barsChart(values, region, colour) {
  const node = svg();
  grid(node);
  shadeRegion(node, region);
  const top = Math.max(...values, 1);
  const width = CHART.w / values.length;
  for (let i = 0; i < values.length; i += 1) {
    const height = (values[i] / top) * (CHART.h - CHART.pad * 2);
    if (height <= 0) continue;
    node.append(shape('rect', {x: i * width, y: CHART.h - CHART.pad - height,
                               width: Math.max(width * 0.9, 0.7), height: height,
                               fill: colour, 'fill-opacity': 0.92}));
  }
  node.append(shape('line', {x1: 0, y1: CHART.h - CHART.pad, x2: CHART.w, y2: CHART.h - CHART.pad,
                             stroke: CHART.axis, 'stroke-width': 1}));
  return node;
}

function legend(items) {
  const row = document.createElement('div');
  row.className = 'chart-legend';
  for (const [label, colour] of items) {
    const item = document.createElement('span');
    if (colour !== 'transparent') {
      const swatch = shape('svg', {width: 10, height: 10, viewBox: '0 0 10 10'});
      swatch.append(shape('rect', {width: 10, height: 10, rx: 2, fill: colour}));
      item.append(swatch);
    }
    item.append(document.createTextNode(label));
    row.append(item);
  }
  return row;
}

function chartBlock(title, note, body, extra) {
  const block = document.createElement('section');
  block.className = 'chart-block';
  const heading = document.createElement('h4');
  heading.textContent = title;
  const caption = document.createElement('p');
  caption.textContent = note;
  block.append(heading, caption, body);
  if (extra) block.append(extra);
  return block;
}

function analysisCharts(data) {
  const wrap = document.createElement('div');
  wrap.className = 'charts';
  const region = data.region;
  const unit = data.kind === 'audio' ? 'sample' : 'carrier value';
  const playable = data.kind !== 'image';

  /* 1. The signal itself, cover and stego, on one scale. */
  const pair = document.createElement('div');
  pair.className = 'chart-pair';
  const waveCharts = {};
  for (const [label, key, colour] of [['Cover', 'cover', CHART.cover], ['Stego', 'stego', CHART.stego]]) {
    const cell = document.createElement('div');
    const tag = document.createElement('span');
    tag.className = 'chart-tag';
    tag.textContent = label;
    waveCharts[key] = waveformChart(data.waveform[key], region, colour);
    cell.append(tag, waveCharts[key]);
    pair.append(cell);
  }
  wrap.waveCharts = waveCharts;
  wrap.append(chartBlock(
    data.kind === 'audio' ? 'Waveform' : 'Signal envelope',
    'Before and after protection, on the same scale. They are indistinguishable — that is the result, '
      + 'not a missing chart. The lighter span marks where the payload actually sits. '
      + (playable ? 'Press play above and the trace lights up under the marker in time with what you hear; '
                  + 'click a trace to seek.' : ''),
    pair));

  /* 2. What actually changed, in raw units. */
  const diff = data.difference;
  wrap.append(chartBlock(
    'Difference from the cover',
    'The largest change to any ' + unit + ' in each slice, in raw units — peaking at ' + diff.max
      + ' across ' + diff.changed.toLocaleString() + ' changed ' + unit + 's, and flat everywhere else '
      + 'because nothing outside the payload was touched. This is the answer to a difference no one can hear.',
    barsChart(diff.values, region, CHART.stego),
    legend([['Changed by up to ' + diff.max + ' units', CHART.stego],
            ['Payload region', 'transparent']])));

  return wrap;
}

/* Fetched when a card is drawn rather than stored with the run: the arrays
   are large and sessionStorage is small. */
async function attachCharts(card, id) {
  const holder = document.createElement('div');
  holder.className = 'charts-loading';
  holder.textContent = 'Measuring…';
  card.append(holder);
  try {
    const body = new FormData();
    body.append('id', id);
    const data = await post('/api/analysis', body);
    const charts = analysisCharts(data);
    holder.replaceWith(charts);

    // The two players sit above the charts, in the order cover then stego.
    const players = card.querySelectorAll('.compare audio, .compare video');
    if (charts.waveCharts && players.length === 2) {
      followPlayback(charts.waveCharts.cover, players[0]);
      followPlayback(charts.waveCharts.stego, players[1]);
    }
  } catch (error) {
    holder.className = 'error';
    holder.textContent = 'Analysis unavailable for this run: ' + error.message;
  }
}
