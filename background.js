// SentinelDLP v3 — Background Service Worker

let _stats = { total: 0, sites: {}, recent: [] };

chrome.storage.local.get('stats', d => { if (d.stats) _stats = d.stats; });

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === 'finding') {
    _stats.total++;
    _stats.sites[msg.host] = (_stats.sites[msg.host] || 0) + msg.count;
    _stats.recent.unshift({ host: msg.host, count: msg.count, ts: msg.ts });
    if (_stats.recent.length > 60) _stats.recent.pop();
    chrome.storage.local.set({ stats: _stats });
    chrome.action.setBadgeText({ text: String(_stats.total), tabId: sender.tab?.id });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  }
  if (msg.type === 'get_stats') return Promise.resolve(_stats);
  if (msg.type === 'clear_stats') {
    _stats = { total: 0, sites: {}, recent: [] };
    chrome.storage.local.set({ stats: _stats });
    chrome.action.setBadgeText({ text: '' });
  }
});
