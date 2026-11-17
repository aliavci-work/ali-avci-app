/* Kendime v1.2 — şifreli yerel kasa + şifreli Google Drive dosyası + Gmail onaylı gönderim.
 * Bu bir statik PWA'dır; e-posta/parola sunucu tarafından kimlik doğrulaması değildir.
 * Parola PBKDF2+AES-GCM şifre çözmek için kullanılır. Parola kalıcı olarak saklanmaz.
 */
(() => {
  'use strict';
  const STORE = 'kendime-state-v1'; // Eski, şifresiz veri için tek seferlik geçiş
  const VAULT_STORE = 'kendime-encrypted-v2';
  const USER_EMAIL = 'aliavci@mail.com';
  const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.send';
  const KDF_ROUNDS = 310000;

  const CLIENT_STORE = 'kendime-google-client-id';
  const FOLDER_NAME = 'Kendime Uygulamalar';
  const FILE_NAME = 'kendime-kasa-v2.json';
  const SCOPE = 'https://www.googleapis.com/auth/drive.file';
  const DB_NAME = 'kendime-db';
  const STUDY_STATUSES = [
    ['review', 'Tekrar Edilecek'],
    ['apply', 'Uygulanacak'],
    ['done', 'Tamamlandı']
  ];
  const STATUS_LABELS = new Map(STUDY_STATUSES);
  const app = document.getElementById('app');
  const dialog = document.getElementById('editor');
  const dialogBody = document.getElementById('editor-content');
  const EMPTY_STATE = () => ({ schema: 1, categories: [], menus: [], notes: [], events: [], outbox: [] });
  let state = EMPTY_STATE();
  let route = 'home';
  let activeCategory = 'all';
  let searchText = '';
  let activeTag = '';
  let activeStatus = '';
  let noteDraft = null;
  let calendarMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
  let selectedDate = localDate(new Date());
  let drawerOpen = false;
  let googleToken = null;
  let googleExpiry = 0;
  let googleClient = null;
  let cloudFileId = null;
  let cloudFolderId = null;
  let syncInProgress = false;
  let syncAgain = false;
  let syncTimer = null;
  let lastSync = null;
  let syncError = '';
  let isStorageReady = false;
  let vaultKey = null;
  let vaultSalt = null;
  let vaultPassword = null; // Yalnızca bu kilidi açık sekmenin RAM'inde, Drive kasasını açmak için.
  let unlocked = false;
  let loginMode = 'setup';
  let authBusy = false;
  let authMessage = '';
  let legacyData = null;
  let localSaveChain = Promise.resolve();
  let gmailClient = null;
  let gmailToken = null;
  let gmailExpiry = 0;
  let mailSending = false;
  let mailError = '';


  function localDate(d) {
    const x = new Date(d);
    return `${x.getFullYear()}-${String(x.getMonth()+1).padStart(2,'0')}-${String(x.getDate()).padStart(2,'0')}`;
  }
  function dateNice(s, opt = {}) {
    if (!s) return '';
    const d = new Date(`${s.slice(0,10)}T12:00:00`);
    return Number.isNaN(d.getTime()) ? s : d.toLocaleDateString('tr-TR', opt);
  }
  function stamp() { return new Date().toISOString(); }
  function uid() { return crypto.randomUUID ? crypto.randomUUID() : `id-${Date.now()}-${Math.random().toString(36).slice(2)}`; }
  function safe(v) { return String(v ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x])); }
  function trimText(v, n=130) { const t = String(v || '').replace(/\s+/g,' ').trim(); return t.length > n ? `${t.slice(0,n)}…` : t; }
  const live = a => (state[a] || []).filter(x => !x.deletedAt);
  const byNewest = (a,b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''));
  const fmtTime = ts => ts ? new Date(ts).toLocaleString('tr-TR',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}) : '';
  const find = (type,id) => (state[type] || []).find(x => x.id === id && !x.deletedAt);
  const count = type => live(type).length;
  const clientId = () => (localStorage.getItem(CLIENT_STORE) || window.KENDIME_CONFIG?.googleClientId || '').trim();

  function bytesToBase64(bytes) {
    let data = '';
    for(let i=0;i<bytes.length;i+=16384) data += String.fromCharCode(...bytes.slice(i,i+16384));
    return btoa(data);
  }
  function base64ToBytes(str) { return Uint8Array.from(atob(str), x => x.charCodeAt(0)); }
  async function deriveKey(password, salt) {
    const material = await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:KDF_ROUNDS,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  async function sealData(value,key,salt) {
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const plaintext=new TextEncoder().encode(JSON.stringify(value));
    const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,plaintext);
    return {kind:'kendime-locked-v2',kdf:'PBKDF2-SHA256',iterations:KDF_ROUNDS,salt:bytesToBase64(salt),iv:bytesToBase64(iv),ciphertext:bytesToBase64(new Uint8Array(encrypted))};
  }
  async function unsealData(envelope,password) {
    if(!envelope || envelope.kind!=='kendime-locked-v2' || envelope.iterations!==KDF_ROUNDS) throw Error('Desteklenmeyen şifreli kayıt biçimi.');
    const salt=base64ToBytes(envelope.salt);
    const key=await deriveKey(password,salt);
    const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:base64ToBytes(envelope.iv)},key,base64ToBytes(envelope.ciphertext));
    return {value:JSON.parse(new TextDecoder().decode(bytes)),key,salt};
  }
  function showAuth() {
    const setup=loginMode==='setup';
    app.innerHTML=`<div class="auth-shell"><section class="auth-card">
      <div class="auth-brand"><div class="brand-icon">AA</div><div><div class="brand-title">Ali Avcı</div><div class="brand-subtitle">KİŞİSEL KAYITLAR</div></div></div>
      <div class="eyebrow">${setup?'İLK KURULUM':'KİLİTLİ ALAN'}</div>
      <h1>${setup?'Parola oluştur':'Giriş'}</h1>
      <p class="auth-description">${setup?'Kayıtları şifrelemek için bir parola belirleyin.':'Kayıtlara erişmek için parolayı girin.'}</p>
      <form id="auth-form" autocomplete="on">
        <label class="field-label" for="auth-email">E-posta</label><input class="field" id="auth-email" name="email" type="email" readonly value="${USER_EMAIL}">
        <label class="field-label" for="auth-pass">Parola</label><input class="field" id="auth-pass" name="password" type="password" minlength="10" required autocomplete="${setup?'new-password':'current-password'}" placeholder="En az 10 karakter">
        ${setup?'<label class="field-label" for="auth-confirm">Parola tekrar</label><input class="field" id="auth-confirm" name="confirm" type="password" minlength="10" required autocomplete="new-password" placeholder="Parolayı tekrar yazın">':''}
        ${authMessage?`<p class="auth-error" role="alert">${safe(authMessage)}</p>`:''}
        <button class="button primary auth-submit" type="submit" ${authBusy?'disabled':''}>${authBusy?'Kontrol ediliyor…':setup?'Parolayı kaydet':'Giriş yap'}</button>
      </form>
      ${legacyData?'<p class="auth-info">Önceki sürümden kayıt bulundu. Parola oluşturulduğunda yerel kayıtlar şifrelenerek aktarılacak.</p>':''}
      <p class="auth-info">Bu giriş bir Google/Firebase hesabı değildir. Parola cihazdaki ve Drive’daki şifreli kayıtları açar. Parola kaybolursa şifreli verilere erişilemez.</p>
    </section></div>`;
  }
  async function submitAuth(form) {
    if(authBusy) return;
    const v=Object.fromEntries(new FormData(form).entries());
    authMessage='';
    if(v.email!==USER_EMAIL) {authMessage='E-posta adresi geçersiz.';showAuth();return;}
    if(String(v.password).length<10) {authMessage='Parola en az 10 karakter olmalı.';showAuth();return;}
    if(loginMode==='setup' && v.password!==v.confirm) {authMessage='Parolalar aynı değil.';showAuth();return;}
    authBusy=true;showAuth();
    try {
      if(loginMode==='setup') {
        // Aynı anda başka sekmede kasa kurulmuşsa üzerine yazma.
        if(await idbGet(VAULT_STORE)) throw Error('Bu tarayıcıda kasa zaten var. Sayfayı yenileyin.');
        vaultSalt=crypto.getRandomValues(new Uint8Array(16));
        vaultKey=await deriveKey(v.password,vaultSalt);
        vaultPassword=v.password;
        state=normalize(legacyData||EMPTY_STATE());
        isStorageReady=true;unlocked=true;
        await saveLocal();
        if(!await idbGet(VAULT_STORE))throw Error('Şifreli kayıt doğrulanamadı, veriler taşınmadı.');
        if(legacyData) await idbDelete(STORE);
        legacyData=null;
      } else {
        const envelope=await idbGet(VAULT_STORE);
        const result=await unsealData(envelope,v.password);
        state=normalize(result.value);
        vaultSalt=result.salt;vaultKey=result.key;vaultPassword=v.password;
        isStorageReady=true;unlocked=true;
      }
      route='home';authBusy=false;render();
      toast(loginMode==='setup'?'Şifreli kasa oluşturuldu.':'Giriş başarılı.');
      // Aynı açık sekmede hâlâ geçerli yetkiler varsa yeniden Google penceresi açmadan devam et.
      if(googleToken && Date.now()<googleExpiry) void syncCloud();
      if(gmailToken && Date.now()<gmailExpiry) void sendPendingMail();
    } catch(err) {
      unlocked=false;isStorageReady=false;state=EMPTY_STATE();vaultKey=null;vaultPassword=null;
      authMessage=err.name==='OperationError'?'Parola yanlış veya şifreli kayıt açılamadı.':(err.message||'Giriş başarısız.');
      authBusy=false;showAuth();
    }
  }
  async function lockApp() {
    if(!unlocked)return;
    try {await localSaveChain;}catch{}
    // Kilitle: yalnızca şifreli kasa oturumunu bitir. Google izinlerini iptal ETME.
    // Token'lar sadece bu açık sekmenin belleğindedir; sekme kapanırsa kaybolurlar.
    // Google erişimini bilerek kaldırmak için Ayarlar > Bağlantıyı kes kullanılır.
    vaultKey=null;vaultSalt=null;vaultPassword=null;
    unlocked=false;isStorageReady=false;state=EMPTY_STATE();closeEditor();loginMode='unlock';authMessage='';showAuth();
  }
  function openDatabase() {
    return new Promise((resolve,reject) => {
      if (!('indexedDB' in window)) return reject(new Error('IndexedDB kullanılamıyor'));
      const req = indexedDB.open(DB_NAME,1);
      req.onupgradeneeded = () => req.result.createObjectStore('data');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function idbGet(key) {
    const db = await openDatabase();
    return new Promise((resolve,reject) => {
      const tx=db.transaction('data','readonly');
      const req=tx.objectStore('data').get(key);
      req.onsuccess=()=>resolve(req.result);
      req.onerror=()=>reject(req.error);
      tx.oncomplete=()=>db.close();
      tx.onerror=()=>reject(tx.error);
    });
  }
  async function idbPut(key,value) {
    const db = await openDatabase();
    return new Promise((resolve,reject) => {
      const tx=db.transaction('data','readwrite');
      tx.objectStore('data').put(value,key);
      tx.oncomplete=()=>{db.close();resolve();};
      tx.onerror=()=>{db.close();reject(tx.error);};
    });
  }
  async function idbDelete(key) {
    const db=await openDatabase();
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('data','readwrite');tx.objectStore('data').delete(key);
      tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>{db.close();reject(tx.error);};
    });
  }
  function normalize(input) {
    const x=input && typeof input==='object' ? input : {};
    const out=EMPTY_STATE();
    for(const type of ['categories','menus','notes','events']) {
      out[type]=Array.isArray(x[type]) ? x[type].filter(z=>z && typeof z==='object' && typeof z.id==='string').map(z=>({...z})) : [];
    }
    out.outbox=Array.isArray(x.outbox)?x.outbox.filter(z=>z&&typeof z==='object'&&typeof z.id==='string').map(z=>({...z})):[];
    return out;
  }
  async function saveLocal() {
    if(!isStorageReady || !unlocked || !vaultKey)return;
    const snapshot=structuredClone(state),key=vaultKey,salt=vaultSalt;
    localSaveChain=localSaveChain.catch(()=>{}).then(async()=>{
      await idbPut(VAULT_STORE,await sealData(snapshot,key,salt));
    });
    try {await localSaveChain;}catch(e){toast(`Şifreli yerel kayıt başarısız: ${e.message}`,true);throw e;}
  }
  function changed() { void saveLocal(); scheduleSync(); render(); }
  function toast(msg,error=false) {
    const host=document.getElementById('toasts');
    const el=document.createElement('div');
    el.className=`toast${error?' error':''}`;
    el.textContent=msg;
    host.append(el);
    setTimeout(()=>el.remove(),4700);
  }
  function upsert(type,entry,touch=true) {
    const at=state[type].findIndex(x=>x.id===entry.id);
    const obj=touch?{...entry,updatedAt:stamp()}:entry;
    if(at>=0) state[type][at]=obj; else state[type].push(obj);
    changed();
  }
  function remove(type,id) {
    const record=find(type,id);
    if(!record) return;
    if(!confirm(`“${record.title || record.name || 'Bu kayıt'}” silinsin mi?`)) return;
    const now=stamp();
    state[type]=state[type].map(x=>x.id===id?{...x,updatedAt:now,deletedAt:now}:x);
    // İlgili kategorinin ya da menünün altındaki kayıtlar saklanır, ancak üst bağlantısı temizlenir.
    if(type==='categories') state.notes=state.notes.map(x=>x.categoryId===id && !x.deletedAt?{...x,categoryId:null,updatedAt:now}:x);
    if(type==='menus') state.notes=state.notes.map(x=>x.menuId===id && !x.deletedAt?{...x,menuId:null,updatedAt:now}:x);
    if(route===`menu:${id}`) route='home';
    if(activeCategory===id) activeCategory='all';
    changed();toast('Kayıt silindi.');
  }
  function clearNoteFilters() { searchText='';activeCategory='all';activeTag='';activeStatus=''; }
  function navigate(next) { route=next; drawerOpen=false;clearNoteFilters();window.scrollTo(0,0);render(); }
  function navItem(id,label,icon) {
    return `<button type="button" class="nav-item ${route===id?'active':''}" data-action="nav" data-id="${safe(id)}"><span class="nav-icon">${safe(icon)}</span><span class="nav-label">${safe(label)}</span></button>`;
  }
  const driveReady = () => Boolean(googleToken && Date.now()<googleExpiry);
  const gmailReady = () => Boolean(gmailToken && Date.now()<gmailExpiry);
  function statusText() {
    if(driveReady() && gmailReady()) return 'Drive + Gmail bağlı';
    if(driveReady()) return 'Drive bağlı';
    if(gmailReady()) return 'Gmail bağlı';
    if(googleToken || gmailToken) return 'Google bağlantısını yenile';
    return 'Yalnızca cihazda';
  }
  function sidebar() {
    return `<div class="overlay ${drawerOpen?'show':''}" data-action="close-drawer"></div>
      <aside class="sidebar ${drawerOpen?'open':''}">
        <div class="brand"><div class="brand-icon">AA</div><div><div class="brand-title">Ali Avcı</div><div class="brand-subtitle">kişisel alanım</div></div></div>
        <div class="side-links">
          ${navItem('home','Ana Sayfa','⌂')}
          ${navItem('notes','Notlarım','▤')}
          ${navItem('calendar','Takvimim','▦')}
        </div>
        <div class="side-title"><span>Özel Menüler</span><button type="button" class="icon-button" data-action="new-menu" title="Yeni menü">＋</button></div>
        <div class="side-links side-custom">${live('menus').sort((a,b)=>(a.title||'').localeCompare(b.title||'','tr')).map(m=>navItem(`menu:${m.id}`,m.title,m.icon||'◈')).join('') || '<p class="hint" style="padding:0 13px">Henüz özel menü yok.</p>'}</div>
        <div class="side-links">${navItem('settings','Ayarlar & Drive','⚙')}</div>
        <div class="side-footer">◉ ${safe(statusText())}<div style="margin-top:6px">${lastSync?`Son eşitleme: ${safe(fmtTime(lastSync))}`:'Kayıtlar cihazda güvenle tutulur.'}</div></div>
      </aside>`;
  }
  function topbar() {
    return `<div class="topbar"><button type="button" class="button mobile-menu" data-action="drawer" aria-label="Menüyü aç">☰</button>
      <span class="eyebrow">KİŞİSEL PANEL</span>
      <div class="top-actions"><span class="pill ${driveReady()&&gmailReady()?'connected':''}">● ${safe(statusText())}</span>
        ${driveReady()&&gmailReady()?'':`<button type="button" class="button primary" data-action="connect-all">Google'ı bağla</button>`}
        <button type="button" class="button" data-action="sync">↻ Eşitle</button><button type="button" class="button" data-action="lock">Kilitle</button></div></div>`;
  }
  function head(title,desc) {return `<div class="eyebrow">KİŞİSEL ÇALIŞMA ALANIN</div><h1 class="page-title">${safe(title)}</h1><p class="page-subtitle">${safe(desc)}</p>`;}
  function empty(text,sub='',action='',label='') {
    return `<div class="empty"><strong>${safe(text)}</strong><div>${safe(sub)}</div>${action?`<button type="button" class="button primary" style="margin-top:16px" data-action="${safe(action)}">＋ ${safe(label)}</button>`:''}</div>`;
  }
  // Search Turkish and English text without case or dotted-I surprises.
  const searchKey = v => String(v??'').normalize('NFC').toLocaleLowerCase('tr-TR').replace(/ı/g,'i');
  const tagKey = searchKey;
  function cleanTags(items) {
    const tags=new Map();
    for(const raw of Array.isArray(items)?items:[]) {
      if(typeof raw!=='string')continue;
      const tag=Array.from(raw.normalize('NFC').trim().replace(/^#+\s*/, '').replace(/\s+/g,' ')).slice(0,30).join('').trim();
      if(tag && !tags.has(tagKey(tag)))tags.set(tagKey(tag),tag);
      if(tags.size===8)break;
    }
    return Array.from(tags.values());
  }
  const noteTags = n => cleanTags(n?.studyTags?.values);
  const noteStatus = n => STATUS_LABELS.has(n?.studyStatus?.value)?n.studyStatus.value:'';
  function cardForNote(n) {
    const cat=find('categories',n.categoryId);
    const status=noteStatus(n),tags=noteTags(n);
    return `<article class="card"><div class="eyebrow">${cat ? safe(cat.name) : (n.menuId?'ÖZEL SAYFA':'NOT')}</div>
       <h3 class="card-title">${safe(n.title || 'Başlıksız')}</h3><p class="card-text">${safe(trimText(n.content,155) || 'İçerik yok')}</p>
       ${status||tags.length?`<div class="note-meta">${status?`<span class="note-badge note-badge--${status}">${STATUS_LABELS.get(status)}</span>`:''}${tags.map(tag=>`<span class="note-badge note-badge--tag">#${safe(tag)}</span>`).join('')}</div>`:''}
       <div class="card-foot"><span>${safe(fmtTime(n.updatedAt))}</span><div class="card-actions"><button class="mini-button" data-action="edit-note" data-id="${safe(n.id)}">Düzenle</button><button class="mini-button" data-action="delete-note" data-id="${safe(n.id)}">Sil</button></div></div></article>`;
  }
  function renderHome() {
    const recent=live('notes').sort(byNewest).slice(0,4);
    const soon=live('events').filter(e=>e.date>=localDate(new Date())).sort((a,b)=>(a.date+(a.time||'')).localeCompare(b.date+(b.time||''))).slice(0,4);
    return `${head('Genel Bakış','Notlar, takvim ve özel menüler.')}
      <section class="hero compact-hero"><div><div class="eyebrow">HIZLI İŞLEMLER</div><h2>Yeni kayıt</h2></div>
      <div class="hero-actions"><button class="button" data-action="new-note">＋ Yeni not</button><button class="button" data-action="new-event">＋ Takvim kaydı</button><button class="button" data-action="new-menu">＋ Özel menü</button></div></section>
      <div class="stats"><div class="stat"><div class="stat-label">Notlar</div><div class="stat-number">${live('notes').filter(n=>!n.menuId).length}</div></div><div class="stat"><div class="stat-label">Takvim kaydı</div><div class="stat-number">${count('events')}</div></div><div class="stat"><div class="stat-label">Özel menü</div><div class="stat-number">${count('menus')}</div></div></div>
      <div class="section-heading"><h2>Son notların</h2><a href="#" data-action="nav" data-id="notes">Tüm notlar →</a></div>
      ${recent.length?`<div class="cards">${recent.map(cardForNote).join('')}</div>`:empty('Henüz not bulunmuyor.','Yeni not eklenebilir.','new-note','Not ekle')}
      <div class="section-heading"><h2>Yaklaşan planların</h2><a href="#" data-action="nav" data-id="calendar">Takvime git →</a></div>
      ${soon.length?`<div class="list">${soon.map(e=>`<div class="list-entry"><div><div class="date-tag">${safe(dateNice(e.date,{day:'numeric',month:'long',weekday:'long'}))} ${safe(e.time||'')}</div><h3>${safe(e.title)}</h3><p>${safe(trimText(e.description,100))}</p></div><div class="card-actions"><button class="mini-button" data-action="edit-event" data-id="${safe(e.id)}">Düzenle</button></div></div>`).join('')}</div>`:empty('Yaklaşan kayıt bulunmuyor.','Yeni takvim kaydı eklenebilir.','new-event','Etkinlik ekle')}`;
  }
  const noteScope = menuId => live('notes').filter(n=>menuId?n.menuId===menuId:!n.menuId);
  const hasNoteFilters = () => Boolean(searchText.trim() || activeCategory!=='all' || activeTag || activeStatus);
  function filterNotes(all,menuId) {
    const query=searchKey(searchText.trim());
    return all.filter(n=>(menuId || activeCategory==='all' || n.categoryId===activeCategory) &&
      (!activeTag || noteTags(n).some(t=>tagKey(t)===activeTag)) &&
      (!activeStatus || noteStatus(n)===activeStatus) &&
      (!query || searchKey(`${n.title||''} ${n.content||''} ${noteTags(n).join(' ')}`).includes(query))).sort(byNewest);
  }
  function renderNoteResults(filtered,menuId) {
    if(filtered.length)return `<div class="cards">${filtered.map(cardForNote).join('')}</div>`;
    if(hasNoteFilters())return empty('Eşleşen kayıt bulunmadı.','Arama veya filtreleri değiştirip tekrar deneyebilirsin.');
    return empty('Burada henüz bir şey yok.','Başlamak için yeni bir kayıt oluştur.','new-note',menuId?'Sayfa ekle':'Not ekle');
  }
  function noteResultCount(filtered,total) {
    return hasNoteFilters()?`${filtered.length} / ${total} kayıt`:`${total} kayıt`;
  }
  function updateNoteSearch() {
    const menuId=route.startsWith('menu:')?route.slice(5):null;
    const all=noteScope(menuId);
    const filtered=filterNotes(all,menuId);
    document.getElementById('note-results').innerHTML=renderNoteResults(filtered,menuId);
    document.getElementById('note-count').textContent=noteResultCount(filtered,all.length);
    document.getElementById('clear-note-filters').disabled=!hasNoteFilters();
  }
  function renderNotes(menuId=null) {
    const menu = menuId ? find('menus',menuId) : null;
    const title=menuId?(menu?.title||'Menü bulunamadı'):'Notlarım';
    const subtitle=menuId?'Bu menüye istediğin kadar sayfa ve metin ekleyebilirsin.':'Kategorilerini aç, düzenle ve aradığın notu kolayca bul.';
    const all=noteScope(menuId);
    const tags=new Map();
    for(const n of all)for(const tag of noteTags(n))if(!tags.has(tagKey(tag)))tags.set(tagKey(tag),tag);
    if(activeTag && !tags.has(activeTag))activeTag='';
    const tagOptions=[...tags].sort((a,b)=>a[1].localeCompare(b[1],'tr'));
    const filtered=filterNotes(all,menuId);
    return `${head(title,subtitle)}
      <div class="toolbar"><div class="filters">${menuId?'':`<button class="chip ${activeCategory==='all'?'active':''}" data-action="filter" data-id="all">Tümü (${all.length})</button>${live('categories').map(c=>`<button class="chip ${activeCategory===c.id?'active':''}" data-action="filter" data-id="${safe(c.id)}">${safe(c.name)} (${all.filter(x=>x.categoryId===c.id).length})</button>`).join('')}<button class="chip" data-action="new-category">＋ Kategori</button>`}</div>
      <div class="top-actions"><input class="search" id="search" type="search" placeholder="Notlarda ara…" value="${safe(searchText)}" aria-label="Notlarda ara"><button class="button primary" data-action="new-note" data-menu="${safe(menuId||'')}">＋ ${menuId?'Yeni sayfa':'Yeni not'}</button>${menu?`<button class="button" data-action="edit-menu" data-id="${safe(menuId)}">Menüyü düzenle</button>`:''}</div></div>
      <div class="note-filter-bar">
        <label class="note-filter-field">Etiket<select id="filter-note-tag" class="field"><option value="">Tüm etiketler</option>${tagOptions.map(([key,label])=>`<option value="${safe(key)}" ${key===activeTag?'selected':''}>${safe(label)}</option>`).join('')}</select></label>
        <label class="note-filter-field">Not durumu<select id="filter-note-status" class="field"><option value="">Tüm durumlar</option>${STUDY_STATUSES.map(([key,label])=>`<option value="${key}" ${key===activeStatus?'selected':''}>${label}</option>`).join('')}</select></label>
        <button id="clear-note-filters" class="button" type="button" data-action="clear-note-filters" ${hasNoteFilters()?'':'disabled'}>Filtreleri temizle</button>
        <span id="note-count" class="note-count" role="status" aria-live="polite">${noteResultCount(filtered,all.length)}</span>
      </div>
      <div id="note-results">${renderNoteResults(filtered,menuId)}</div>`;
  }
  function monthGrid() {
    const year=calendarMonth.getFullYear(), month=calendarMonth.getMonth();
    const first=new Date(year,month,1); const offset=(first.getDay()+6)%7;
    const begin=new Date(year,month,1-offset);
    const now=localDate(new Date());
    const cells=[];
    for(let i=0;i<42;i++) {
      const d=new Date(begin);d.setDate(begin.getDate()+i);
      const key=localDate(d),e=live('events').filter(x=>x.date===key).sort((a,b)=>(a.time||'').localeCompare(b.time||''));
      cells.push(`<button class="day ${d.getMonth()!==month?'dim':''} ${key===now?'today':''} ${key===selectedDate?'selected':''}" data-action="select-day" data-id="${key}"><span class="day-number">${d.getDate()}</span>${e.slice(0,2).map(x=>`<span class="day-event">${safe(x.time||'')} ${safe(x.title)}</span>`).join('')}${e.length>2?`<span class="day-event">+${e.length-2} daha</span>`:''}</button>`);
    }
    return `<div class="calendar-grid">${['Pzt','Sal','Çar','Per','Cum','Cmt','Paz'].map(x=>`<div class="calendar-weekday">${x}</div>`).join('')}${cells.join('')}</div>`;
  }
  function renderCalendar() {
    const es=live('events').filter(x=>x.date===selectedDate).sort((a,b)=>(a.time||'').localeCompare(b.time||''));
    const month=calendarMonth.toLocaleDateString('tr-TR',{month:'long',year:'numeric'});
    return `${head('Takvimim','Günlerini, randevularını ve yapılacaklarını bir bakışta gör.')}
      <div class="toolbar"><div class="top-actions"><button class="button" data-action="prev-month">‹</button><strong style="font:normal 25px Georgia,serif">${safe(month)}</strong><button class="button" data-action="next-month">›</button><button class="button" data-action="today">Bugün</button></div><button class="button primary" data-action="new-event">＋ Etkinlik</button></div>
      <div class="calendar-layout"><div>${monthGrid()}</div><aside class="agenda"><div class="eyebrow">SEÇİLİ GÜN</div><h3>${safe(dateNice(selectedDate,{day:'numeric',month:'long',weekday:'long'}))}</h3>
       ${es.length?es.map(e=>`<div class="agenda-item"><div class="date-tag">${safe(e.time||'Tüm gün')}</div><strong>${safe(e.title)}</strong><p>${safe(e.description||'')}</p><div class="card-actions"><button class="mini-button" data-action="edit-event" data-id="${safe(e.id)}">Düzenle</button><button class="mini-button" data-action="delete-event" data-id="${safe(e.id)}">Sil</button></div></div>`).join(''):'<p class="hint">Bu güne ait kayıt yok.</p>'}
       <button class="button" style="margin-top:18px;width:100%" data-action="new-event">＋ Bu güne ekle</button></aside></div>`;
  }
  function renderSettings() {
    const id=clientId();const connected=googleToken&&Date.now()<googleExpiry;
    return `${head('Ayarlar & Google Drive','Bulut bağlantını ve kişisel veri yedeklerini yönet.')}
      <section class="settings-block" style="margin-bottom:18px"><h2>Google bağlantıları</h2>
        <p>Drive ve Gmail için daha önce verdiğin izinleri tek işlemde yeniden kullanabilirsin. Google erişimi süreli olduğu için tarayıcı tamamen kapandıktan sonra yeniden bağlama gerekebilir; ancak her defasında ayrı ayrı izin vermen gerekmez.</p>
        <div class="top-actions"><button class="button primary" data-action="connect-all">${driveReady()&&gmailReady()?'Google bağlantılarını yenile':'Drive + Gmail tek tıkla bağlan'}</button></div>
        <p class="hint">Google erişim anahtarları cihazda kalıcı olarak saklanmaz. “Kilitle” yalnızca kasayı kilitler; Google iznini kaldırmak için “Bağlantıyı kes” kullanılır.</p>
      </section>
      <div class="settings-grid"><section class="settings-block"><h2>Google Drive bağlantısı</h2><p>Drive verileri <strong>${safe(FOLDER_NAME)}/${safe(FILE_NAME)}</strong> dosyasına şifrelenerek kaydedilir. Google hesap parolası uygulamaya girilmez.</p>
        <div class="pill ${connected?'connected':''}">● ${safe(statusText())}</div>
        <label class="field-label" for="client-id">Google OAuth Web Client ID</label>
        <input class="field" id="client-id" type="text" autocomplete="off" spellcheck="false" placeholder="123456...apps.googleusercontent.com" value="${safe(id)}">
        <p class="hint">Client ID bir sır değildir. Google Cloud'da Web uygulaması türünde oluşturulmalıdır. Client Secret buraya yazılmaz.</p>
        <div class="top-actions"><button class="button" data-action="save-client">Kimliği kaydet</button><button class="button primary" data-action="connect">${connected?'Yeniden bağlan':'Google hesabımı bağla'}</button></div>
        <div class="top-actions" style="margin-top:12px"><button class="button" data-action="sync">Şimdi eşitle</button>${connected?'<button class="button" data-action="disconnect">Bağlantıyı kes</button>':''}</div>
        ${lastSync?`<p class="hint">Son başarılı eşitleme: ${safe(fmtTime(lastSync))}</p>`:''}
        ${syncError?`<p style="color:#b53028;font-size:12px">Son hata: ${safe(syncError)}</p>`:''}
      </section><section class="settings-block"><h2>Notları e-postaya gönder</h2>
        <p>Yeni veya güncellenen notların bir kopyası <strong>${USER_EMAIL}</strong> adresine gönderilir. Gönderim için ayrıca Gmail hesabına <strong>yalnızca e-posta gönderme</strong> izni vermen gerekir.</p>
        <div class="pill ${gmailToken&&Date.now()<gmailExpiry?'connected':''}">● ${gmailToken&&Date.now()<gmailExpiry?'Gmail yetkili':'Gmail bağlı değil'}</div>
        <p class="hint">Bekleyen gönderi: ${state.outbox.length}. Tarayıcı kapalıyken gönderim gerçekleşmez. E-postalar gönderilemediğinde kuyrukta kalır. Gmail API etkinleştirilmelidir.</p>
        <div class="top-actions"><button class="button primary" data-action="connect-gmail">Gmail gönderme izni ver</button><button class="button" data-action="send-pending">Bekleyenleri gönder</button></div>
        ${mailError?`<p style="color:#b53028;font-size:12px">Son gönderim hatası: ${safe(mailError)}</p>`:''}
      </section><section class="settings-block"><h2>Yedek & geri yükleme</h2><p>JSON dışa aktarma ve içe alma yapılabilir. <strong>İndirilen JSON dosyası şifreli değildir.</strong> Yedek dosyasını güvenli yerde tutun.</p>
        <div class="top-actions"><button class="button" data-action="export">↓ JSON yedeğini indir</button><button class="button" data-action="import">↑ JSON içe aktar</button></div>
        <input id="import-file" type="file" accept=".json,application/json" class="hidden">
        <p class="hint">İçe aktarma kayıt kimliklerine göre birleştirilir. Şifreli Drive kasası için aynı parola gerekir.</p>
      </section><section class="settings-block"><h2>Bu sürümde neler var?</h2><p>Notlar ve kategoriler, özel menü/sayfalar, aylık takvim, cihazda çevrimdışı kayıt, Drive eşitleme, Android PWA yükleme ve JSON yedek.</p><p><strong>Sınırlar:</strong> Bu parola bir sunucu hesabı değildir; şifreli kasanın anahtarıdır. E-posta gönderimi yalnızca Gmail bağlantısı açıkken mümkündür. Dosya ekleri, Google Takvim ve tarayıcı kapalıyken eşitleme henüz yoktur.</p></section></div>`;
  }
  function render() {
    if(!isStorageReady || !unlocked) {showAuth();return;}
    const main=route==='home'?renderHome():route==='notes'?renderNotes():route==='calendar'?renderCalendar():route==='settings'?renderSettings():route.startsWith('menu:')?renderNotes(route.slice(5)):renderHome();
    const focused=document.activeElement;
    const restoreSearch=focused?.id==='search' && main.includes('id="search"');
    const selection=restoreSearch?[focused.selectionStart,focused.selectionEnd]:null;
    app.innerHTML=`<div class="shell">${sidebar()}<main class="main">${topbar()}${main}<div class="about">Ali Avcı v1.2.4 · Şifreli yerel kayıt · Şifreli Google Drive yedeği · İzinli Gmail gönderimi.</div></main></div>`;
    if(restoreSearch){const search=document.getElementById('search');search?.focus({preventScroll:true});if(selection[0]!==null)search?.setSelectionRange(...selection);}
  }
  function showEditor(html) { dialogBody.innerHTML=html;dialog.showModal();setTimeout(()=>dialog.querySelector('input:not([type=hidden]),textarea')?.focus(),40); }
  function closeEditor(){dialog.close();dialogBody.innerHTML='';noteDraft=null;}
  function formHead(title){return `<div class="dialog-header"><h2>${safe(title)}</h2><button class="button ghost" type="button" data-action="close-dialog">✕</button></div>`;}
  function noteEditor(id=null,menuId=null) {
    const n=id?find('notes',id):null;
    const menu=menuId || n?.menuId || null;
    const categories=live('categories');
    const category=n?.categoryId||(!id && !menu && route==='notes' && activeCategory!=='all'?activeCategory:null);
    noteDraft={id:n?.id||'',title:n?.title||'',content:n?.content||'',categoryId:category,menuId:menu,tags:noteTags(n),status:noteStatus(n)};
    showEditor(`${formHead(n?'Kaydı düzenle':menu?'Yeni sayfa':'Yeni not')}<form id="note-form">
      <input type="hidden" name="id" value="${safe(n?.id||'')}"><input type="hidden" name="menuId" value="${safe(menu||'')}">
      <label class="field-label">Başlık</label><input name="title" class="field" maxlength="180" required placeholder="Örneğin: Haftalık plan" value="${safe(n?.title||'')}">
      ${menu?'':`<label class="field-label">Kategori</label><select class="field" name="categoryId"><option value="">Kategorisiz</option>${categories.map(c=>`<option value="${safe(c.id)}" ${category===c.id?'selected':''}>${safe(c.name)}</option>`).join('')}</select>`}
      <div class="note-editor-meta">
        <div><label class="field-label" for="note-tags">Etiketler</label><input id="note-tags" class="field" name="studyTags" type="text" maxlength="500" aria-describedby="note-tag-hint" placeholder="Örn. gramer, kelime" value="${safe(noteDraft.tags.join(', '))}"><small id="note-tag-hint" class="hint">Virgülle ayır. En çok 8 etiket, her biri en çok 30 karakter.</small></div>
        <div><label class="field-label" for="note-status">Not durumu</label><select id="note-status" class="field" name="studyStatus"><option value="">Durum yok</option>${STUDY_STATUSES.map(([value,label])=>`<option value="${value}" ${noteDraft.status===value?'selected':''}>${label}</option>`).join('')}</select></div>
      </div>
      <label class="field-label">İçerik</label><textarea name="content" class="field" rows="11" placeholder="Aklındakileri buraya yaz…">${safe(n?.content||'')}</textarea>
      <div class="dialog-actions"><button class="button" type="button" data-action="close-dialog">Vazgeç</button><button class="button primary" type="submit">Kaydet</button></div></form>`);
  }
  function categoryEditor(id=null) {
    const c=id?find('categories',id):null;
    showEditor(`${formHead(c?'Kategoriyi düzenle':'Yeni kategori')}<form id="category-form"><input type="hidden" name="id" value="${safe(c?.id||'')}">
      <label class="field-label">Kategori adı</label><input class="field" name="name" required maxlength="80" placeholder="Kişisel, İş, Fikirler…" value="${safe(c?.name||'')}">
      <div class="dialog-actions">${c?`<button type="button" class="button danger" data-action="delete-category" data-id="${safe(c.id)}">Sil</button>`:''}<button type="button" class="button" data-action="close-dialog">Vazgeç</button><button class="button primary" type="submit">Kaydet</button></div></form>`);
  }
  function menuEditor(id=null) {
    const m=id?find('menus',id):null;
    showEditor(`${formHead(m?'Menüyü düzenle':'Yeni özel menü')}<form id="menu-form"><input type="hidden" name="id" value="${safe(m?.id||'')}">
      <label class="field-label">Menü başlığı</label><input name="title" class="field" required maxlength="80" placeholder="Projelerim, Tariflerim, Öğrenme…" value="${safe(m?.title||'')}">
      <label class="field-label">Simge (tek emoji veya kısa işaret)</label><input name="icon" class="field" maxlength="5" placeholder="◈" value="${safe(m?.icon||'◈')}">
      <div class="dialog-actions">${m?`<button type="button" class="button danger" data-action="delete-menu" data-id="${safe(m.id)}">Sil</button>`:''}<button type="button" class="button" data-action="close-dialog">Vazgeç</button><button class="button primary" type="submit">Kaydet</button></div></form>`);
  }
  function eventEditor(id=null) {
    const e=id?find('events',id):null;
    showEditor(`${formHead(e?'Etkinliği düzenle':'Takvime ekle')}<form id="event-form"><input type="hidden" name="id" value="${safe(e?.id||'')}">
      <label class="field-label">Etkinlik başlığı</label><input class="field" name="title" required maxlength="180" placeholder="Görüşme, ders, hatırlatma…" value="${safe(e?.title||'')}">
      <div class="form-row"><div><label class="field-label">Tarih</label><input class="field" name="date" type="date" required value="${safe(e?.date||selectedDate)}"></div><div><label class="field-label">Saat (isteğe bağlı)</label><input class="field" name="time" type="time" value="${safe(e?.time||'')}"></div></div>
      <label class="field-label">Açıklama</label><textarea class="field" name="description" rows="5" placeholder="Detaylar…">${safe(e?.description||'')}</textarea>
      <div class="dialog-actions"><button class="button" type="button" data-action="close-dialog">Vazgeç</button><button class="button primary" type="submit">Kaydet</button></div></form>`);
  }
  function formData(form) { return Object.fromEntries(new FormData(form).entries()); }
  const sameTags=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  function metadataStamp(previous,now) {
    const ms=Date.parse(previous?.updatedAt);
    return Number.isFinite(ms) && ms>=Date.parse(now) && ms<8640000000000000?new Date(ms+1).toISOString():now;
  }
  function applyNoteDraft(v,id) {
    const draft=noteDraft;
    const old=v.id?find('notes',id):null;
    if(!draft || draft.id!==v.id || (v.id && !old)){
      toast('Not artık düzenlenemiyor. Listeyi yeniden aç.',true);
      return false;
    }
    const title=v.title.trim();
    if(!title){toast('Not başlığını gir.',true);return false;}
    const input={title,content:v.content||'',categoryId:v.menuId?null:(v.categoryId||null),menuId:v.menuId||null};
    const submitTags=cleanTags(String(v.studyTags||'').split(/[,\n]/u));
    const submitStatus=STATUS_LABELS.has(v.studyStatus)?v.studyStatus:'';
    const entry={...old,id};
    for(const key of Object.keys(input)){
      entry[key]=old && input[key]===draft[key]?old[key]??(key.endsWith('Id')?null:''):input[key];
    }
    const bodyChanged=!old || Object.keys(input).some(k=>entry[k] !== (old[k]??(k.endsWith('Id')?null:'')));
    const tagsChanged=!sameTags(submitTags,draft.tags) && !sameTags(submitTags,noteTags(old));
    const statusChanged=submitStatus!==draft.status && submitStatus!==noteStatus(old);
    if(!bodyChanged && !tagsChanged && !statusChanged)return true;
    const now=stamp();
    if(tagsChanged)entry.studyTags={values:submitTags,updatedAt:metadataStamp(old?.studyTags,now)};
    if(statusChanged)entry.studyStatus={value:submitStatus,updatedAt:metadataStamp(old?.studyStatus,now)};
    if(bodyChanged)state.outbox.push({id:uid(),noteId:id,title:entry.title,content:entry.content,kind:old?'Güncellendi':'Yeni not',savedAt:now});
    upsert('notes',entry,bodyChanged);
    if(bodyChanged)void sendPendingMail();
    return true;
  }
  document.addEventListener('submit',e=>{
    const f=e.target;const formId=f.getAttribute('id');
    if(formId==='auth-form'){e.preventDefault();void submitAuth(f);return;}
    if(!unlocked){e.preventDefault();return;}if(!formId || !['note-form','category-form','menu-form','event-form'].includes(formId)) return;
    e.preventDefault();const v=formData(f);const id=v.id||uid();
    if(formId==='note-form') {
      if(!applyNoteDraft(v,id))return;
    }
    if(formId==='category-form') {const old=find('categories',id)||{};upsert('categories',{...old,id,name:v.name.trim()});}
    if(formId==='menu-form') {const old=find('menus',id)||{};upsert('menus',{...old,id,title:v.title.trim(),icon:v.icon.trim()||'◈'});route=`menu:${id}`;}
    if(formId==='event-form') {const old=find('events',id)||{};upsert('events',{...old,id,title:v.title.trim(),date:v.date,time:v.time||'',description:v.description||''});selectedDate=v.date;calendarMonth=new Date(`${v.date.slice(0,7)}-01T12:00:00`);}
    closeEditor();render();toast('Kaydedildi.');
  });
  document.addEventListener('click',async e=>{
    const el=e.target.closest('[data-action]');if(!el)return;
    if(!unlocked)return;
    if(el.tagName==='A')e.preventDefault();
    const a=el.dataset.action,id=el.dataset.id;
    try {
      switch(a) {
        case 'nav':navigate(id);break;
        case 'drawer':drawerOpen=!drawerOpen;render();break;
        case 'close-drawer':drawerOpen=false;render();break;
        case 'new-note':noteEditor(null,el.dataset.menu|| (route.startsWith('menu:')?route.slice(5):null));break;
        case 'edit-note':noteEditor(id);break;
        case 'delete-note':remove('notes',id);break;
        case 'new-category':categoryEditor();break;
        case 'delete-category':closeEditor();remove('categories',id);break;
        case 'new-menu':menuEditor();break;
        case 'edit-menu':menuEditor(id);break;
        case 'delete-menu':closeEditor();remove('menus',id);break;
        case 'new-event':eventEditor();break;
        case 'edit-event':eventEditor(id);break;
        case 'delete-event':remove('events',id);break;
        case 'close-dialog':closeEditor();break;
        case 'filter':activeCategory=id;render();break;
        case 'clear-note-filters':clearNoteFilters();render();document.getElementById('search')?.focus();break;
        case 'select-day':selectedDate=id;render();break;
        case 'today':calendarMonth=new Date(new Date().getFullYear(),new Date().getMonth(),1);selectedDate=localDate(new Date());render();break;
        case 'prev-month':calendarMonth=new Date(calendarMonth.getFullYear(),calendarMonth.getMonth()-1,1);render();break;
        case 'next-month':calendarMonth=new Date(calendarMonth.getFullYear(),calendarMonth.getMonth()+1,1);render();break;
        case 'lock':await lockApp();break;
        case 'connect-all':connectAllGoogle();break;
        case 'connect-gmail':connectGmail();break;
        case 'send-pending':await sendPendingMail(true);break;
        case 'save-client':saveClientId();break;
        case 'connect':connectGoogle();break;
        case 'disconnect':disconnectGoogle();break;
        case 'sync':if(!googleToken||Date.now()>=googleExpiry) {navigate('settings');toast('Önce Google hesabını bağla.',true);} else await syncCloud();break;
        case 'export':downloadBackup();break;
        case 'import':document.getElementById('import-file')?.click();break;
      }
    } catch(err){toast(err.message||'Beklenmeyen hata oluştu.',true);console.error(err);}
  });
  document.addEventListener('input',e=>{
    if(unlocked && e.target.id==='search') {searchText=e.target.value;updateNoteSearch();}
  });
  document.addEventListener('change',async e=>{
    if(!unlocked)return;
    if(e.target.id==='filter-note-tag'){activeTag=e.target.value;updateNoteSearch();return;}
    if(e.target.id==='filter-note-status'){activeStatus=e.target.value;updateNoteSearch();return;}
    if(e.target.id!=='import-file')return;
    const file=e.target.files?.[0];if(!file)return;
    try {
      const content=JSON.parse(await file.text());
      if(!content || content.schema!==1 || !['categories','menus','notes','events'].every(k=>Array.isArray(content[k])))throw Error('Geçerli bir eski sürüm yedeği değil.');
      if(!unlocked || !confirm('Yedekteki kayıtlar mevcut verilerle birleştirilsin mi?'))return;
      state=mergeStates(state,content);changed();toast('Yedek içe aktarıldı.');
    } catch(err){toast(`İçe aktarma başarısız: ${err.message}`,true);}
  });
  function downloadBackup() {
    const data=JSON.stringify(state,null,2);
    const url=URL.createObjectURL(new Blob([data],{type:'application/json'}));
    const a=document.createElement('a');a.href=url;a.download=`ali-avci-yedek-${localDate(new Date())}.json`;a.click();
    setTimeout(()=>URL.revokeObjectURL(url),2000);
  }
  function newerNoteMeta(a,b) {
    if(!a?.updatedAt)return b;
    if(!b?.updatedAt)return a;
    if(a.updatedAt!==b.updatedAt)return a.updatedAt>b.updatedAt?a:b;
    return JSON.stringify(a)>JSON.stringify(b)?a:b;
  }
  function mergeStates(one,two) {
    const a=normalize(one),b=normalize(two),result=EMPTY_STATE();
    for(const type of ['categories','menus','notes','events']) {
      const map=new Map();
      for(const x of [...a[type],...b[type]]) {
        const prev=map.get(x.id);
        // Aynı anda üretilen zaman damgaları için silinmiş kayıt önceliklidir.
        const bodyWins=!prev || String(x.updatedAt||'')>String(prev.updatedAt||'') || (String(x.updatedAt||'')===String(prev.updatedAt||'') && x.deletedAt && !prev.deletedAt);
        const winner=bodyWins?x:prev;
        if(type==='notes' && prev){
          const merged={...winner};
          for(const key of ['studyTags','studyStatus']){
            const metadata=newerNoteMeta(prev[key],x[key]);
            if(metadata)merged[key]=metadata;
          }
          map.set(x.id,merged);
        } else if(bodyWins)map.set(x.id,winner);
      }
      result[type]=Array.from(map.values()).sort((x,y)=>x.id.localeCompare(y.id));
    }
    result.outbox=a.outbox;
    return result;
  }
  function canonical(x) {const c=mergeStates(EMPTY_STATE(),x);delete c.outbox;return JSON.stringify(c);}
  function connectGmail() {
    const id=clientId();
    if(!id)throw Error('Önce Ayarlar & Drive içinde Google OAuth Web Client ID kaydet.');
    if(!window.google?.accounts?.oauth2)throw Error('Google giriş kitaplığı yüklenemedi.');
    gmailClient=window.google.accounts.oauth2.initTokenClient({
      client_id:id,scope:GMAIL_SCOPE,
      callback:response=>{
        if(response.error || !response.access_token){mailError=response.error||'Gmail izni verilmedi.';toast(mailError,true);render();return;}
        if(!window.google.accounts.oauth2.hasGrantedAllScopes(response,GMAIL_SCOPE)){mailError='Gmail gönderme izni verilmedi.';render();return;}
        gmailToken=response.access_token;gmailExpiry=Date.now()+(Number(response.expires_in)||3300)*1000-60000;
        mailError='';render();toast('Gmail izni alındı. Bekleyen notlar gönderiliyor.');void sendPendingMail();
      },error_callback:()=>toast('Gmail giriş penceresi tamamlanamadı.',true)
    });
    gmailClient.requestAccessToken({prompt:''});
  }
  function encodeMail(item) {
    const subject=`Ali Avcı | ${item.kind}: ${item.title}`;
    const heading=`İşlem: ${item.kind}\nTarih: ${new Date(item.savedAt).toLocaleString('tr-TR')}\nBaşlık: ${item.title}\n\n${item.content}`;
    const subjectEncoded='=?UTF-8?B?'+bytesToBase64(new TextEncoder().encode(subject))+'?=';
    const body=bytesToBase64(new TextEncoder().encode(heading)).match(/.{1,76}/g)?.join('\r\n')||'';
    const raw=`To: ${USER_EMAIL}\r\nSubject: ${subjectEncoded}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${body}\r\n`;
    return bytesToBase64(new TextEncoder().encode(raw)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
  async function sendPendingMail(manual=false) {
    if(!unlocked || mailSending)return;
    if(!gmailToken || Date.now()>=gmailExpiry){
      if(manual){mailError='Gmail izni yok veya süresi doldu. Önce Gmail gönderme izni ver.';render();toast(mailError,true);}
      return;
    }
    if(!state.outbox.length){if(manual)toast('Bekleyen e-posta yok.');return;}
    mailSending=true;mailError='';let sent=0;
    try {
      while(state.outbox.length && gmailToken && Date.now()<gmailExpiry && unlocked){
        const record=state.outbox[0];
        const res=await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send',{
          method:'POST',headers:{Authorization:`Bearer ${gmailToken}`,'Content-Type':'application/json'},
          body:JSON.stringify({raw:encodeMail(record)})
        });
        if(!res.ok){let msg='';try{const info=await res.json();msg=info.error?.message||'';}catch{};
          if(res.status===401)gmailExpiry=0;
          throw Error(`Gmail HTTP ${res.status}${msg?': '+msg.slice(0,180):''}`);
        }
        state.outbox.shift();sent++;await saveLocal();
      }
      if(sent)toast(`${sent} not e-postası Gmail üzerinden gönderildi.`);
    }catch(err){mailError=err.message||String(err);toast(`E-posta gönderilemedi: ${mailError}`,true);}
    finally {mailSending=false;render();}
  }
  function saveClientId() {
    const value=document.getElementById('client-id')?.value.trim()||'';
    if(value && !/^\d+-[a-z0-9_-]+\.apps\.googleusercontent\.com$/i.test(value))throw Error('Client ID beklenen Google biçiminde değil.');
    localStorage.setItem(CLIENT_STORE,value);googleClient=null;toast('Client ID cihazına kaydedildi.');render();
  }
  function connectGoogle() {
    const id=clientId();
    if(!id)throw Error('Önce Google OAuth Web Client ID girip kaydet.');
    if(!window.google?.accounts?.oauth2)throw Error('Google giriş kitaplığı yüklenemedi. İnternet bağlantını kontrol et.');
    // Bu çağrı kullanıcının butona basmasıyla tetiklenir, popup engelleyicilerle uyumludur.
    googleClient=window.google.accounts.oauth2.initTokenClient({
      client_id:id,scope:SCOPE,
      callback:async response=>{
        if(response.error){toast(`Google izin hatası: ${response.error}`,true);return;}
        if(!response.access_token || !window.google.accounts.oauth2.hasGrantedAllScopes(response,SCOPE)) {toast('Drive dosya izni verilmedi.',true);return;}
        googleToken=response.access_token;
        googleExpiry=Date.now()+(Number(response.expires_in)||3300)*1000-60000;
        cloudFileId=null;cloudFolderId=null;syncError='';render();
        toast('Google yetkisi alındı. Drive eşitleniyor…');
        await syncCloud();
      },
      error_callback:()=>toast('Google giriş penceresi tamamlanamadı.',true)
    });
    googleClient.requestAccessToken({prompt:''});
  }
  function connectAllGoogle() {
    const id=clientId();
    if(!id)throw Error('Önce Ayarlar & Drive bölümünde Google OAuth Web Client ID kaydet.');
    if(!window.google?.accounts?.oauth2)throw Error('Google giriş kitaplığı yüklenemedi. İnternet bağlantını kontrol et.');
    // Bu işlem sadece düğmeye basılarak başlatılır. Google izinleri ilk defa isteniyorsa Google sorar.
    const bothScopes=[SCOPE,GMAIL_SCOPE];
    googleClient=window.google.accounts.oauth2.initTokenClient({
      client_id:id,scope:bothScopes.join(' '),
      callback:async response=>{
        if(response.error || !response.access_token){
          toast('Google bağlantısı kurulamadı: '+(response.error||'Erişim izni verilmedi.'),true);return;
        }
        const expiry=Date.now()+(Number(response.expires_in)||3300)*1000-60000;
        const driveGranted=window.google.accounts.oauth2.hasGrantedAllScopes(response,SCOPE);
        const gmailGranted=window.google.accounts.oauth2.hasGrantedAllScopes(response,GMAIL_SCOPE);
        // Her kullanıcı izni ayrı ayrı geri çevirebilir: kısmi izni başarı gibi gösterme.
        if(driveGranted){googleToken=response.access_token;googleExpiry=expiry;cloudFileId=null;cloudFolderId=null;syncError='';}
        if(gmailGranted){gmailToken=response.access_token;gmailExpiry=expiry;mailError='';}
        render();
        if(driveGranted && gmailGranted)toast('Drive ve Gmail bağlandı. Eşitleme başlatılıyor.');
        else if(driveGranted)toast('Drive bağlandı; Gmail izni verilmedi.',true);
        else if(gmailGranted)toast('Gmail bağlandı; Drive izni verilmedi.',true);
        else {toast('Drive veya Gmail için erişim izni verilmedi.',true);return;}
        if(driveGranted)await syncCloud();
        if(gmailGranted)void sendPendingMail();
      },
      error_callback:()=>toast('Google giriş penceresi tamamlanamadı.',true)
    });
    // prompt:'' önceki izni yeniden sormaz; yeni bir kapsam gerekiyorsa Google onay gösterir.
    googleClient.requestAccessToken({prompt:''});
  }
  function disconnectGoogle() {
    // Birleşik erişim anahtarı iki hizmete de yetki verebilir; bunu açıkça belirt.
    const tokens=[...new Set([googleToken,gmailToken].filter(Boolean))];
    if(window.google?.accounts?.oauth2)for(const token of tokens)window.google.accounts.oauth2.revoke(token,()=>{});
    googleToken=null;googleExpiry=0;gmailToken=null;gmailExpiry=0;
    cloudFileId=null;cloudFolderId=null;syncError='';mailError='';
    render();toast('Google Drive ve Gmail erişimi kesildi. Yerel notlar silinmedi.');
  }
  async function driveRequest(url,opts={}) {
    if(!googleToken || Date.now()>=googleExpiry)throw Error('Google oturumu süresi doldu. Tekrar bağlan.');
    const headers=new Headers(opts.headers||{});headers.set('Authorization',`Bearer ${googleToken}`);
    const res=await fetch(url,{...opts,headers});
    if(!res.ok) {
      let info='';try{const j=await res.json();info=j.error?.message||'';}catch{info=await res.text().catch(()=>'');}
      if(res.status===401){googleExpiry=0;throw Error('Google oturumu sona erdi. Yeniden bağlan.');}
      throw Error(`Drive HTTP ${res.status}${info?`: ${info.slice(0,250)}`:''}`);
    }
    if(res.status===204)return null;
    const t=await res.text();return t?JSON.parse(t):null;
  }
  async function listDrive(q) {
    const url=`https://www.googleapis.com/drive/v3/files?${new URLSearchParams({q,fields:'nextPageToken,files(id,name,mimeType,parents)',pageSize:'100',spaces:'drive'})}`;
    // Sayfalama genellikle gerekmez; yüzlerce aynı isimli dosyada ilk eşleşme kullanılır.
    const response=await driveRequest(url);
    return response.files || [];
  }
  async function createDriveMetadata(data) {
    return driveRequest('https://www.googleapis.com/drive/v3/files?fields=id,name',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  }
  async function ensureFolder() {
    if(cloudFolderId)return cloudFolderId;
    const q=`name = '${FOLDER_NAME.replace(/'/g,"\\'")}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
    const old=await listDrive(q);
    const folder=old[0] || await createDriveMetadata({name:FOLDER_NAME,mimeType:'application/vnd.google-apps.folder'});
    cloudFolderId=folder.id;
    return folder.id;
  }
  async function createJSONFile(folderId,data) {
    const boundary=`kendime_${uid().replace(/-/g,'')}`;
    const metadata=JSON.stringify({name:FILE_NAME,mimeType:'application/json',parents:[folderId]});
    const body=new Blob([
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n`,
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(data)}\r\n--${boundary}--\r\n`
    ],{type:`multipart/related; boundary=${boundary}`});
    return driveRequest('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name',{method:'POST',headers:{'Content-Type':`multipart/related; boundary=${boundary}`},body});
  }
  async function saveJSONFile(id,data) {
    return driveRequest(`https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(id)}?uploadType=media&fields=id,modifiedTime`,{method:'PATCH',headers:{'Content-Type':'application/json; charset=UTF-8'},body:JSON.stringify(data)});
  }
  async function getJSONFile(id) {return driveRequest(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(id)}?alt=media`);}
  function scheduleSync() {
    if(!googleToken || Date.now()>=googleExpiry)return;
    clearTimeout(syncTimer);syncTimer=setTimeout(()=>void syncCloud(),1800);
  }
  async function syncCloud() {
    if(!unlocked)return;
    if(!googleToken || Date.now()>=googleExpiry) {syncError='Google oturumu sona erdi. Yeniden bağlan.';render();return;}
    if(!navigator.onLine) {syncError='Çevrimdışı. Veriler şifreli olarak cihazda saklandı.';render();return;}
    if(syncInProgress){syncAgain=true;return;}
    syncInProgress=true;syncAgain=false;
    try {
      const folder=await ensureFolder();
      if(!cloudFileId){
        const q=`name = '${FILE_NAME}' and '${folder}' in parents and trashed = false`;
        const files=await listDrive(q);cloudFileId=files[0]?.id||null;
      }
      if(!cloudFileId){
        // Eski sürümde Drive'a bağlanmış kullanıcılar için şifresiz v1 dosyası korunarak içe alınır.
        const oldFiles=await listDrive(`name = 'kendime-veriler-v1.json' and '${folder}' in parents and trashed = false`);
        if(oldFiles.length){
          const previous=await getJSONFile(oldFiles[0].id);
          if(previous && previous.schema===1){
            state=mergeStates(state,previous);await saveLocal();
            toast('Önceki Drive kayıtları aktarıldı. Eski şifresiz v1 dosyasını yedek kontrolünden sonra Drive’dan kaldırabilirsiniz.');
          }else throw Error('Önceki Drive verisi okunamadı. Üzerine yazma durduruldu.');
        }
        const cloudCopy=mergeStates(EMPTY_STATE(),state);cloudCopy.outbox=[];
        const encrypted=await sealData(cloudCopy,await deriveKey(vaultPassword,vaultSalt),vaultSalt);
        const record=await createJSONFile(folder,encrypted);cloudFileId=record.id;
      } else {
        const encrypted=await getJSONFile(cloudFileId);
        const remote=(await unsealData(encrypted,vaultPassword)).value;
        if(remote.schema!==1)throw Error('Drive dosyası uyumsuz. Üzerine yazma engellendi.');
        const combined=mergeStates(state,remote);
        if(canonical(combined)!==canonical(remote)){
          const cloudCopy=mergeStates(EMPTY_STATE(),combined);cloudCopy.outbox=[];
          await saveJSONFile(cloudFileId,await sealData(cloudCopy,await deriveKey(vaultPassword,vaultSalt),vaultSalt));
        }
        state=mergeStates(state,combined);await saveLocal();
      }
      syncError='';lastSync=stamp();render();
    } catch(err){
      syncError=err.name==='OperationError'?'Drive kasası açılamadı: Parolalar farklı olabilir. Üzerine yazılmadı.':(err.message||String(err));
      toast(`Drive eşitleme başarısız: ${syncError}`,true);render();
    } finally {syncInProgress=false;if(syncAgain){syncAgain=false;scheduleSync();}}
  }
  async function init() {
    if(!crypto?.subtle){app.innerHTML='<p class="auth-error">Güvenli şifreleme kullanılamıyor. HTTPS veya localhost üzerinden açın.</p>';return;}
    try {
      const encrypted=await idbGet(VAULT_STORE);
      loginMode=encrypted?'unlock':'setup';
      if(!encrypted)legacyData=await idbGet(STORE)||null;
      showAuth();
    }catch(err){app.innerHTML=`<main class="main"><h1 class="page-title">Yerel depolama açılamadı</h1><p>${safe(err.message)}</p></main>`;return;}
    if('serviceWorker' in navigator && (location.protocol==='https:'||location.hostname==='localhost'))navigator.serviceWorker.register('./sw.js').catch(()=>{});
    window.addEventListener('online',()=>{if(unlocked){toast('Bağlantı geri geldi.');scheduleSync();void sendPendingMail();}});
    window.addEventListener('offline',()=>{if(unlocked)toast('Çevrimdışı. Kayıtlar cihazda şifreli tutulacak.');});
    document.addEventListener('visibilitychange',()=>{if(!document.hidden && unlocked){if(googleToken&&Date.now()<googleExpiry)scheduleSync();void sendPendingMail();}});
    setInterval(()=>{if(!document.hidden && unlocked){if(googleToken&&Date.now()<googleExpiry)void syncCloud();if(gmailToken&&Date.now()<gmailExpiry)void sendPendingMail();}},60000);
  }
  void init();
})();
