// popup.js — SentinelDLP v3

const I={
  zh:{sub:'本機偵測 · 資料不外傳 · by Kerr',on:'保護中',off:'已暫停',
      total:'累計偵測',sites:'涉及網站',recent:'最近記錄',empty:'尚無記錄',
      enable:'🔔 啟用偵測',enable_sub:'關閉後停止所有監控',
      clear:'🗑 清除記錄',suppress:'此網站暫停偵測',
      suppressed:h=>`✓ ${h} 已暫停`,
      just_now:'剛才',mins:n=>`${n}分前`,hrs:n=>`${n}時前`,lang_btn:'EN'},
  en:{sub:'Local detection · No data sent · by Kerr',on:'Protected',off:'Paused',
      total:'Detections',sites:'Sites',recent:'Recent alerts',empty:'No records yet',
      enable:'🔔 Enable detection',enable_sub:'Turn off to pause monitoring',
      clear:'🗑 Clear records',suppress:'Trust this site',
      suppressed:h=>`✓ ${h} trusted`,
      just_now:'just now',mins:n=>`${n}m ago`,hrs:n=>`${n}h ago`,lang_btn:'中文'}
};
let lang=localStorage.getItem('sdlp-lang')||(navigator.language.startsWith('zh')?'zh':'en');
const enableChk=document.getElementById('enable-chk');
const dot=document.getElementById('status-dot');

function applyLang(){
  const L=I[lang];
  ['h-sub','lbl-total','lbl-sites','lbl-recent','empty-msg','lbl-enable','lbl-enable-sub'].forEach(id=>{
    const k={
      'h-sub':'sub','lbl-total':'total','lbl-sites':'sites',
      'lbl-recent':'recent','empty-msg':'empty',
      'lbl-enable':'enable','lbl-enable-sub':'enable_sub'
    }[id];
    if(document.getElementById(id))document.getElementById(id).textContent=L[k];
  });
  document.getElementById('status-text').textContent=enableChk.checked?L.on:L.off;
  document.getElementById('btn-clear').textContent=L.clear;
  document.getElementById('btn-suppress').textContent=L.suppress;
  document.getElementById('lang-btn').textContent=L.lang_btn;
}

function toggleLang(){
  lang=lang==='zh'?'en':'zh';
  localStorage.setItem('sdlp-lang',lang);
  applyLang();
  loadStats();
}

chrome.storage.sync.get(['enabled','suppressed'],d=>{
  if(d.enabled!==undefined)enableChk.checked=d.enabled;
  dot.className='dot'+(enableChk.checked?'':' off');
  applyLang();
});

enableChk.onchange=()=>{
  chrome.storage.sync.set({enabled:enableChk.checked});
  dot.className='dot'+(enableChk.checked?'':' off');
  document.getElementById('status-text').textContent=I[lang][enableChk.checked?'on':'off'];
};

async function loadStats(){
  chrome.runtime.sendMessage({type:'get_stats'}, (s) => {
    if(!s)return;
    const L=I[lang];
    document.getElementById('stat-total').textContent=s.total||0;
    document.getElementById('stat-sites').textContent=Object.keys(s.sites||{}).length;
    const list=document.getElementById('recent-list');
    if(!s.recent?.length){list.innerHTML=`<div class="empty">${L.empty}</div>`;return;}
    list.innerHTML=s.recent.slice(0,8).map(r=>{
      const m=Math.round((Date.now()-r.ts)/60000);
      const time=m<1?L.just_now:m<60?L.mins(m):L.hrs(Math.round(m/60));
      return`<div class="rec-item"><span class="rec-host">${r.host}</span><span class="rec-cnt">${r.count}</span><span class="rec-time">${time}</span></div>`;
    }).join('');
  });
}

document.getElementById('btn-clear').onclick=()=>{
  chrome.runtime.sendMessage({type:'clear_stats'}, () => {
    setTimeout(loadStats,150);
  });
};

document.getElementById('btn-suppress').onclick=()=>{
  chrome.tabs.query({active:true,currentWindow:true},tabs=>{
    if(!tabs[0] || !tabs[0].url.startsWith('http'))return;
    try {
      const host=new URL(tabs[0].url).hostname;
      chrome.storage.sync.get('suppressed',d=>{
        const list=[...(d.suppressed||[])];
        if(!list.includes(host))list.push(host);
        chrome.storage.sync.set({suppressed:list});
        document.getElementById('btn-suppress').textContent=I[lang].suppressed(host);
      });
    } catch(e) {}
  });
};

document.getElementById('lang-btn').addEventListener('click', toggleLang);

loadStats();
applyLang();
