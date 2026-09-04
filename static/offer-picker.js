(()=>{
const root=document.querySelector('[data-offer-picker]');if(!root)return;
const button=root.querySelector('[data-offer-request]'),clock=root.querySelector('[data-offer-clock]'),dialog=root.querySelector('dialog'),error=root.querySelector('[data-offer-error]');
let next=Date.parse(root.dataset.next),pending=false,busy=false;
function tick(){const seconds=Math.max(0,Math.ceil((next-Date.now())/1000));clock.textContent=pending?'Your alternative offer is ready to review.':seconds?`Next offer available in ${Math.floor(seconds/3600)}h ${String(Math.floor(seconds%3600/60)).padStart(2,'0')}m ${String(seconds%60).padStart(2,'0')}s`:'You can request another offer. Your current discount remains available.';button.hidden=!pending&&seconds>0;button.disabled=busy||(!pending&&seconds>0);button.textContent=pending?'Review another offer':'Show another offer'}
function update(data){if(!data.active){root.hidden=true;return}next=Date.parse(data.next_offer_at);pending=!!data.pending_percent;root.querySelector('[data-current-percent]').textContent=data.percent+'%';root.querySelector('[data-new-percent]').textContent=data.pending_percent+'%';tick()}
async function request(action){const response=await fetch('/api/billing/offer',{method:action?'POST':'GET',headers:action?{'Content-Type':'application/json','X-CSRF-Token':root.dataset.csrf}:{},body:action?JSON.stringify({action,_csrf_token:root.dataset.csrf}):undefined});const data=await response.json();if(!response.ok)throw Error(data.error||'Offer unavailable. Please try again.');update(data);return data}
button.addEventListener('click',async()=>{busy=true;tick();error.textContent='';try{const data=await request('propose');if(data.active)dialog.showModal()}catch(e){error.textContent=e.message}finally{busy=false;tick()}});
root.querySelector('.offer-close').addEventListener('click',()=>dialog.close());
root.querySelectorAll('[data-offer-action]').forEach(b=>b.addEventListener('click',async()=>{const actions=root.querySelectorAll('[data-offer-action]');actions.forEach(x=>x.disabled=true);try{await request(b.dataset.offerAction);dialog.close();location.reload()}catch(e){root.querySelector('[data-dialog-error]').textContent=e.message;actions.forEach(x=>x.disabled=false)}}));
tick();const interval=setInterval(tick,1000);request().catch(e=>{error.textContent=e.message;button.disabled=true;clearInterval(interval)});
document.addEventListener('visibilitychange',()=>{if(!document.hidden)request().catch(()=>{})});
})();
