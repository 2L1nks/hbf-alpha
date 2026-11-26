// Headless unit test for aggregation, direction separation and graph layout.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const file=require('node:path').join(__dirname,'../controller/static/topology.js');
const env={window:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),env);
const graph=env.window.HBFTopology;
const hosts=[{id:'a',label:'Alpha',ip:'10.0.0.1',grp:'MGMT',enabled:1},
             {id:'b',label:'Beta',ip:'10.0.0.2',grp:'DB',enabled:1}];
const policies=[];for(let i=1;i<=80;i++)policies.push({id:'P'+i,name:'rule'+i,src:'a',dst:'b',proto:'tcp',port:8000+i,enabled:1});
policies.push({id:'P81',name:'opposite',src:'b',dst:'a',proto:'tcp',port:9999,enabled:1});
const model={nodes:hosts,groups:[{id:'MGMT'},{id:'DB'}],edges:[
 {source:'a',target:'b',rules:policies.slice(0,80)},
 {source:'b',target:'a',rules:[policies[80]]}]};
graph.state.mode='hosts';graph.state.status='active';
let v=graph.graphView(model);assert.equal(v.edges.length,2);
assert.equal(v.edges.find(e=>e.source==='h:a').count,80);
const geo=graph.layout(v);for(const n of v.nodes)assert.ok(geo.positions.has(n.id));
const a=geo.positions.get('h:a'),b=geo.positions.get('h:b');
assert.notEqual(graph.edgePath(a,b,true).label.y,graph.edgePath(b,a,true).label.y);
graph.state.mode='groups';v=graph.graphView(model);
assert.equal(v.nodes.length,2);assert.equal(v.edges.length,2);
graph.state.port='8080';v=graph.graphView(model);assert.equal(v.edges.length,1);assert.equal(v.edges[0].count,1);
console.log('Topology JS tests passed');
// More than two policies: two visual lanes + an overflow button; self loops
// must be visible without creating/deploying local-host policies.
graph.state.mode='hosts';graph.state.port='';graph.state.proto='all';
const pair=graph.graphView(model).edges.find(e=>e.source==='h:a');
assert.deepEqual(Array.from(graph.visibleEdgeSlots(pair).lanes),[-1,1]);
assert.equal(graph.visibleEdgeSlots(pair).overflow,true);
assert.deepEqual(Array.from(graph.visibleEdgeSlots({rules:[policies[0]]}).lanes),[0]);
assert.equal(graph.visibleEdgeSlots({rules:policies.slice(0,2)}).overflow,false);
const self=graph.edgePath(a,a,false,[],1);
assert.ok(self.d.includes(' C ')&&self.d.startsWith('M '));
const other=graph.edgePath(a,a,false,[],-1);
assert.notEqual(self.d,other.d);
console.log('Grid / lanes / self-loop tests passed');
