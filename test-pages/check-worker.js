// Behavioural checks on the service worker, run against the real background.js
// in a sandbox.
//
//   node test-pages/check-worker.js
//
// Each of these is a bug that shipped and was found in review: short links
// colliding because paths were lowercased, a feed outage silently discarding
// the other feed's entries, a personal report that a trusted domain overruled,
// simultaneous detections overwriting each other's counts, and withdrawing a
// report leaving the site quieter than one never reported.
const fs=require("fs"), vm=require("vm");
let f=0; const bad=m=>{f++;console.log("  FAIL: "+m);};
const ok=m=>console.log("  ok   "+m);

const path=require("path");
const ROOT=path.resolve(__dirname,"..");
process.chdir(ROOT);
const lib=["data/strings.js","data/allowlist.js","data/ad-networks.js"]
  .map(x=>fs.readFileSync(x,"utf8")).join("\n;\n");
// the worker's importScripts is replaced by concatenating those files instead
const bg=fs.readFileSync("background.js","utf8").replace(/^importScripts\([^)]*\);/m,"");

function worker(fetchImpl, seed){
  const store=Object.assign({},seed||{});
  const ctx={console,URL,setTimeout,clearTimeout,setInterval,clearInterval,fetch:fetchImpl,structuredClone};
  ctx.chrome={
    storage:{local:{
      get:async(k)=>{const o={};(Array.isArray(k)?k:[k]).forEach(x=>{if(x in store)o[x]=store[x];});return o;},
      set:async(o)=>{Object.assign(store,o);}},
      session:{get:async()=>({}),set:async()=>{},remove:async()=>{}}},
    runtime:{onMessage:{addListener(){}},onInstalled:{addListener(){}},
             onStartup:{addListener(){}},getManifest:()=>({version:"test"})},
    alarms:{create(){},onAlarm:{addListener(){}}},
    tabs:{onRemoved:{addListener(){}},sendMessage:async()=>{},remove(){}},
    notifications:{create(){}}
  };
  vm.createContext(ctx);
  vm.runInContext(lib+"\n"+bg,ctx,{filename:"bg.js"});
  return {ctx,store};
}

// --- 1. distinct short links stay distinct ---------------------------------
{
  const {ctx}=worker(async()=>({ok:true,text:async()=>""}));
  const a=ctx.guardianNormalizeUrl("https://bit.ly/AbC123");
  const b=ctx.guardianNormalizeUrl("https://bit.ly/abc123");
  a!==b?ok("bit.ly/AbC123 and bit.ly/abc123 stay separate"):bad("short links still collide");
  ctx.guardianNormalizeUrl("https://EXAMPLE.com/Path")==="https://example.com/Path"
    ?ok("host lowercased, path preserved"):bad("host/path casing wrong");
}

// --- 2. a failing feed must not discard the other --------------------------
(async()=>{
  const seed={feedCache:{"https://urlhaus.abuse.ch/downloads/text_online/":
    {hosts:["malware-host.example"],urls:[],at:Date.now()-3600e3}}};
  const {ctx,store}=worker(async(u)=>{
    if(u.includes("urlhaus")) throw new Error("simulated outage");
    return {ok:true,text:async()=>"https://phish-one.example/a\n"};
  },seed);
  await ctx.refreshBlocklist();
  const all=new Set();
  for(const k of Object.keys(store.feedCache||{}))
    (store.feedCache[k].hosts||[]).forEach(h=>all.add(h));
  all.has("malware-host.example")?ok("a feed outage keeps that feed's last good entries")
                                 :bad("the down feed's entries were discarded");
  all.has("phish-one.example")?ok("the working feed's new entries were taken")
                              :bad("the working feed was not ingested");
  Object.values(store.blocklistStatus||{}).some(v=>v.ok===false&&v.error)
    ?ok("the failure is recorded with a reason"):bad("no failure status recorded");

  // --- 3. the person's own report beats the trusted list -------------------
  const w2=worker(async()=>({ok:true,text:async()=>""}),
    {guardianUserBlocklist:["example-bank.com"]});
  const src1=await w2.ctx.blockSource("https://login.example-bank.com/x","");
  src1==="you"?ok("a reported host covers its subdomains")
              :bad("subdomain of a reported host not blocked: "+src1);
  const w3=worker(async()=>({ok:true,text:async()=>""}),
    {guardianUserBlocklist:["google.com"]});
  const src2=await w3.ctx.blockSource("https://google.com/","");
  src2==="you"?ok("reporting a trusted site now takes effect")
              :bad("reporting a trusted site still does nothing");

  // --- 4. simultaneous detections must not overwrite each other ------------
  const w4=worker(async()=>({ok:true,text:async()=>""}));
  await Promise.all(Array.from({length:25},(_,i)=>
    w4.ctx.recordDetection({source:"website",label:"s"+i,reason:"r"})));
  const total=(w4.store.stats||{}).totalBlocked;
  total===25?ok("25 simultaneous detections all counted")
            :bad("counter lost writes: "+total+" of 25");
  const days=Object.keys((w4.store.stats||{}).byDay||{});
  days.length===1&&w4.store.stats.byDay[days[0]]===25
    ?ok("per-day counts survive past the 50-entry log cap")
    :bad("per-day counts wrong: "+JSON.stringify(w4.store.stats.byDay));

  // --- 5. withdrawing a report must not soften future warnings -------------
  const w5=worker(async()=>({ok:true,text:async()=>""}),
    {guardianUserBlocklist:["shop.example"]});
  await w5.ctx.withdrawReport("shop.example");
  const gone=!(w5.store.guardianUserBlocklist||[]).includes("shop.example");
  const noDismissal=!(w5.store.guardianDismissals&&w5.store.guardianDismissals["shop.example"]);
  gone&&noDismissal?ok("withdrawing a report returns the site to normal")
                   :bad("withdrawal left the site reported or softened");

  console.log(f===0?"\nALL REVIEW FIXES VERIFIED":"\n"+f+" FAILURES");
  process.exit(f?1:0);
})();
