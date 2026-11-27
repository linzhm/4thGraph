"use strict";

const model = JSON.parse(document.getElementById("workbench-data").textContent);
const byId = new Map(model.candidates.map(row => [row.id, row]));
const en = [
  "Compare CPN paths", "Candidates", "Eligible", "Excluded", "Replayed", "All", "Find a path…", "CPN graph",
  "Logical", "Transactions", "Candidate inspector", "Estimated path", "Measured path", "Max lock", "Stages",
  "Download plan", "Download receipt", "Planning report", "No matching candidates.", "No graph was compiled.",
  "No replay recorded", "Recorded regtest", "Select a node to inspect its ports", "Inputs", "Outputs",
  "Why excluded", "Rebuild this candidate with the planning report to export its plan.", "Controls rejected", "current", "Node",
  "Source", "Destination", "Authorizers", "Stage backend", "Outpoint", "Amount", "Lock size", "Type", "Stage role", "Forth word",
  "Computation", "Constraints", "External information", "Committed state", "Workflow root", "Handoff",
  "Continuation UTXO", "Ordered receipt in the same transaction", "Current input stack",
  "Published receipt", "Funding transaction", "Authenticated spend preimage", "Role signatures", "Proof packet",
  "Deployment argument", "Witness operand", "Spendable output", "Unspendable output", "Public signals", "Entire R1CS assignment is public",
];
const zh = [
  "比较 CPN 路径", "候选", "可构建", "已淘汰", "已复放", "全部", "搜索路径…", "CPN 图",
  "逻辑", "交易", "候选详情", "估算总字节", "实测总字节", "最大锁", "阶段",
  "下载计划", "下载回执", "规划报告", "没有符合条件的候选。", "该候选没有已构建的图。",
  "暂无复放", "Regtest 记录", "选择节点查看端口", "输入", "输出",
  "淘汰原因", "从规划报告重建此候选后即可导出计划。", "已拒绝的反例", "初始值", "节点",
  "来源", "去向", "授权角色", "阶段后端", "输出点", "金额", "锁大小", "类型", "阶段职责", "Forth 词",
  "计算", "约束", "外部信息", "承诺状态", "工作流根", "交接载体",
  "可花费的后继 UTXO", "同笔交易的有序回执", "当前输入的栈",
  "公开回执", "入金交易", "已认证的花费原像", "角色签名", "证明包",
  "部署参数", "见证操作数", "可花费输出", "不可花费输出", "公开信号", "公开完整 R1CS 赋值",
];
let lang = "en";
let filter = "all";
let view = "logical";
let selected = model.selected ?? model.candidates[0].id;
let activeNode = null;
const $ = id => document.getElementById(id);
const label = index => (lang === "en" ? en : zh)[index];

function element(tag, text, klass) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (klass) node.className = klass;
  return node;
}

function svg(tag, attrs, text) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  if (text !== undefined) node.textContent = text;
  return node;
}

function bytes(value) {
  return value == null ? "—" : new Intl.NumberFormat(lang).format(value) + " B";
}

function graphModel() {
  const nodes = new Map();
  const edges = [];
  function node(id, title, kind, detail, spendable = true) {
    if (!nodes.has(id)) nodes.set(id, {id, title, kind, detail, spendable, inputs: [], outputs: [], ports: []});
    return id;
  }
  function link(from, output, to, input, facts = []) {
    const source = nodes.get(from), target = nodes.get(to);
    if (!source.outputs.includes(output)) source.outputs.push(output);
    if (!target.inputs.includes(input)) target.inputs.push(input);
    source.ports.push({direction: 24, name: output, peer: target.title, peerId: target.id, peerPort: input, facts});
    target.ports.push({direction: 23, name: input, peer: source.title, peerId: source.id, peerPort: output, facts});
    edges.push({source, output, target, input});
  }
  const candidate = byId.get(selected);
  const graph = candidate.graph;
  if (graph && view === "physical") {
    const tx = step => "tx:" + step;
    const place = (step, slot) => "utxo:" + step + ":" + slot;
    const recorded = model.packages[selected]?.transactions;
    function facts(step, slot, type) {
      const output = recorded?.[step]?.outputs[slot];
      const fields = [[37, type]];
      if (output) fields.push([34, output.outpoint], [35, output.satoshis.toLocaleString(lang) + " sat"],
        [36, bytes(output.script_bytes)]);
      if (output?.state_u32 !== undefined) fields.push([43, "u32 · " + output.state_u32], [44, output.root_txid]);
      return fields;
    }
    const templates = [...graph.transactions, ...graph.refunds.map(item => ({
      step: item.step, inputs: [{from: item.from, authorizers: [item.authorizer]}], outputs: [item.output], executes: [],
    }))];
    for (const row of templates) {
      const transition = nodes.get(node(tx(row.step), row.step, "transition", row.executes.join(" + ") || "Transaction"));
      const roles = [...new Set(row.inputs.flatMap(input => input.authorizers ?? []))];
      const related = candidate.assertions?.filter(stage => stage.transaction === row.step) ?? [];
      const external = row.step === "deploy" ? [label(50)] : [label(51) + " · " + (candidate.sighash_family ?? model.sighash)];
      if (row.step === "deploy" && recorded?.deploy) external.push(...recorded.deploy.inputs);
      if (roles.length) external.push(label(52) + " · " + roles.join(", "));
      for (const stage of related.filter(entry => entry.backend !== "script")) {
        external.push(label(53) + " · " + stage.stage + " · " + stage.backend);
      }
      external.push(...(row.external_inputs ?? []));
      transition.facts = [[40, related.map(stage => stage.stage + " → " + stage.word).join(" · ") || "—"],
        [41, row.guards?.join(" · ") || "—"], [42, external.join(" · ")]];
      for (const out of row.outputs) {
        const output = nodes.get(node(place(row.step, out.vout), out.place, "place", out.kind, out.spendable));
        output.facts = [[41, label(out.spendable ? 56 : 57)]];
        if (out.kind === "state" || out.kind === "receipt") output.facts.push([45, label(out.kind === "state" ? 46 : 49)]);
        link(tx(row.step), "vout " + out.vout, place(row.step, out.vout), "produced",
          facts(row.step, out.vout, out.kind));
      }
    }
    for (const row of templates) {
      row.inputs.forEach(({from, authorizers}, vin) => {
        const origin = place(from.step, from.vout);
        const stages = candidate.assertions?.filter(stage => stage.transaction === row.step && stage.vin === vin) ?? [];
        const details = facts(from.step, from.vout, nodes.get(origin).detail);
        if (authorizers?.length) details.push([32, authorizers.join(", ")]);
        if (stages.length) details.push([33, stages.map(stage => stage.stage + " · " + stage.backend).join(", ")]);
        link(origin, row.step + " vin " + vin, tx(row.step), "vin " + vin, details);
      });
    }
  } else if (graph) {
    const place = name => "var:" + name;
    const step = name => "stage:" + name;
    for (const input of graph.inputs) {
      const external = nodes.get(node(place(input.name), input.name, "place", input.type));
      external.facts = [[42, input.name === graph.inputs[0].name ? label(54) + " · " + model.current : label(55)]];
    }
    const assertions = new Map((candidate.assertions ?? []).map(item => [item.stage, item]));
    for (const stage of graph.stages) {
      const assertion = assertions.get(stage.name);
      const id = node(step(stage.name), stage.name, "transition", assertion?.backend ?? stage.word);
      const role = candidate.stage_roles?.find(item => item.stage === stage.name)?.role;
      const effect = ports => ports.map(port => port.name + ": " + port.type).join(", ");
      nodes.get(id).definition = model.words[stage.name];
      nodes.get(id).facts = [[40, effect(stage.inputs) + " → " + effect(stage.outputs)],
        [39, stage.word + " · " + (model.words[stage.name]?.location ?? stage.source.line)], [32, stage.authorizer]];
      if (assertion) nodes.get(id).facts.push([41, assertion.policy + " · " + assertion.binding]);
      const proof = candidate.stage_evidence?.find(item => item.statement.stage === stage.name);
      if (proof) {
        const operands = proof.statement.witnesses.map(([name, privateValue]) => name + (privateValue ? " (private)" : ""));
        nodes.get(id).facts.push([42, [label(53) + " · " + proof.backend, ...operands].join(" · ")]);
        nodes.get(id).facts.push([58, proof.statement.public.join(", ")]);
        if (proof.backend === "r1cs") nodes.get(id).facts.push([41, label(59)]);
      }
      if (role) nodes.get(id).facts.unshift([38, role]);
      for (const output of stage.outputs) {
        node(place(output.name), output.name, "place", output.type);
        link(step(stage.name), output.name, place(output.name), "from " + stage.name, [[37, output.type]]);
      }
    }
    for (const stage of graph.stages) {
      for (const input of stage.inputs) link(place(input.name), stage.name, step(stage.name), input.name, [[37, input.type]]);
    }
    for (const edge of graph.dependencies) {
      const producer = assertions.get(edge.producer), consumer = assertions.get(edge.consumer);
      if (producer && consumer) {
        const medium = producer.transaction !== consumer.transaction ? 46 : producer.vin !== consumer.vin ? 47 : 48;
        nodes.get(place(edge.value)).facts = [[45, label(medium)]];
      }
    }
  } else if (candidate.evidence_graph) {
    for (const item of candidate.evidence_graph.nodes) {
      node("proof:" + item.id, item.id, "transition", item.backend);
      const claim = node("claim:" + item.id, item.proves, "place", "Statement");
      link("proof:" + item.id, item.proves, claim, "proved");
    }
    for (const item of candidate.evidence_graph.nodes) {
      for (const [dep, claim] of Object.entries(item.requires)) {
        link("claim:" + dep, item.id, "proof:" + item.id, claim);
      }
    }
  }
  return {nodes, edges};
}

function layout({nodes, edges}) {
  const pending = new Map([...nodes.keys()].map(key => [key, 0]));
  const outgoing = new Map([...nodes.keys()].map(key => [key, []]));
  for (const edge of edges) {
    pending.set(edge.target.id, pending.get(edge.target.id) + 1);
    outgoing.get(edge.source.id).push(edge);
  }
  const queue = [...nodes.values()].filter(node => pending.get(node.id) === 0);
  for (const node of queue) node.layer = 0;
  for (const node of queue) {
    for (const {target} of outgoing.get(node.id)) {
      target.layer = Math.max(target.layer ?? 0, node.layer + 1);
      pending.set(target.id, pending.get(target.id) - 1);
      if (pending.get(target.id) === 0) queue.push(target);
    }
  }
  if (queue.length !== nodes.size) return null;
  const layers = new Map();
  for (const node of queue) {
    if (!layers.has(node.layer)) layers.set(node.layer, []);
    layers.get(node.layer).push(node);
    node.height = Math.max(node.kind === "place" ? 58 : 73, 26 + 17 * Math.max(node.inputs.length, node.outputs.length));
  }
  const totalHeight = rows => rows.reduce((height, node) => height + node.height + 32, -32);
  const height = Math.max(390, ...[...layers.values()].map(rows => totalHeight(rows) + 42));
  for (const [layer, rows] of layers) {
    let y = (height - totalHeight(rows)) / 2;
    for (const node of rows) {
      node.x = 23 + layer * 184;
      node.y = y;
      y += node.height + 32;
    }
  }
  return {width: Math.max(layers.size * 184 + 12, 450), height, nodes: queue, edges};
}

function renderGraph(focus = false) {
  const canvas = $("canvas");
  const graph = graphModel();
  const geometry = layout(graph);
  if (!geometry || !graph.nodes.size) {
    canvas.replaceChildren(element("p", label(19), "empty"));
    return;
  }
  const {width, height, nodes, edges} = geometry;
  const plot = svg("svg", {viewBox: "0 0 " + width + " " + height, "aria-label": label(7)});
  const defs = svg("defs", {});
  const marker = svg("marker", {id: "arrow", viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 6,
    markerHeight: 6, orient: "auto"});
  marker.append(svg("path", {d: "M 0 1 L 9 5 L 0 9 Z", fill: "#395169"}));
  defs.append(marker);
  plot.append(defs);
  const boxWidth = 137;
  const portY = (node, idx, n) => node.y + node.height * (idx + 1) / (n + 1);
  for (const {source, output, target, input} of edges) {
    const x = source.x + boxWidth, y = portY(source, source.outputs.indexOf(output), source.outputs.length);
    const endX = target.x - 5, endY = portY(target, target.inputs.indexOf(input), target.inputs.length);
    const mid = (x + endX) / 2;
    const incident = activeNode === source.id || activeNode === target.id;
    const wire = svg("path", {class: incident ? "wire incident" : "wire", "marker-end": "url(#arrow)",
      d: "M " + x + " " + y + " C " + mid + " " + y + ", " + mid + " " + endY + ", " + endX + " " + endY});
    wire.append(svg("title", {}, source.title + " · " + output + " → " + target.title + " · " + input));
    plot.append(wire);
  }
  for (const node of nodes) {
    const group = svg("g", {class: "node " + node.kind + (node.spendable ? "" : " unspendable"),
      role: "button", tabindex: 0, "aria-label": node.kind + " " + node.title, "aria-pressed": node.id === activeNode});
    group.append(svg("rect", {x: node.x, y: node.y, width: boxWidth, height: node.height,
      rx: node.kind === "place" ? 26 : 7}));
    group.append(svg("title", {}, node.title + " · " + node.detail));
    const cx = node.x + boxWidth / 2;
    group.append(svg("text", {x: cx, y: node.y + 23, "text-anchor": "middle", class: "node-title"},
      node.title.length > 16 ? node.title.slice(0, 15) + "…" : node.title));
    const detail = node.detail.length > 20 ? node.detail.slice(0, 19) + "…" : node.detail;
    group.append(svg("text", {x: cx, y: node.y + 42, "text-anchor": "middle", class: "node-detail"}, detail));
    for (const [ports, x] of [[node.inputs, node.x], [node.outputs, node.x + boxWidth]]) {
      ports.forEach((name, index) => {
        const y = portY(node, index, ports.length);
        const socket = svg("circle", {cx: x, cy: y, r: 3.7, class: "socket"});
        socket.append(svg("title", {}, name));
        group.append(socket);
        if (/^vin |^vout /.test(name)) {
          const left = x === node.x;
          group.append(svg("text", {x: x + (left ? -7 : 7), y: y - 5,
            "text-anchor": left ? "end" : "start", class: "node-port"}, name));
        }
      });
    }
    function selectNode() {
      activeNode = activeNode === node.id ? null : node.id;
      renderGraph(activeNode !== null);
      renderInspector();
    }
    group.addEventListener("click", selectNode);
    group.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectNode();
      }
    });
    plot.append(group);
  }
  canvas.replaceChildren(plot);
  if (focus) plot.querySelector('[aria-pressed="true"]')?.focus();
}

function save(name, content) {
  const url = URL.createObjectURL(new Blob([content], {type: "application/json"}));
  const link = element("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function download(text, filename, data, klass) {
  const button = element("button", text, klass);
  button.disabled = data == null;
  button.addEventListener("click", () => save(filename, typeof data === "string" ? data : JSON.stringify(data, null, 2)));
  return button;
}

function description(title, rows) {
  const block = element("section", undefined, "details");
  const list = element("ul");
  block.append(element("h3", title), list);
  rows.forEach(([name, extra]) => {
    const item = element("li", name);
    if (extra) item.append(element("small", extra));
    list.append(item);
  });
  return block;
}

function renderInspector() {
  const row = byId.get(selected), pkg = model.packages[selected] ?? {};
  const panel = $("inspector");
  panel.replaceChildren(element("h2", label(10)), element("p", selected, "path mono"));
  const metrics = element("dl", undefined, "metrics");
  for (const [name, size] of [[11, row.cost?.whole_path_bytes], [12, pkg.bytes], [13, row.max_lock_bytes]]) {
    const entry = element("div");
    entry.append(element("dt", label(name)), element("dd", bytes(size), "mono"));
    metrics.append(entry);
  }
  panel.append(metrics);
  if (pkg.receipt) panel.append(element("p", label(21) + (pkg.checks.length ? " · " + label(27) + " " + pkg.checks.length : ""), "hint"));
  if (row.exclusions?.length) {
    panel.append(description(label(25), row.exclusions.map(item => [item.code, [item.stage, item.message].filter(Boolean).join(" · ")])));
  }
  const node = graphModel().nodes.get(activeNode);
  if (node) {
    panel.append(description(label(29) + " · " + node.title, [
      [node.kind === "place" ? "Place" : "Transition", node.detail],
      ...(node.facts ?? []).map(([key, value]) => [label(key), value]),
    ]));
    if (node.definition?.source) {
      const code = element("section", undefined, "details");
      code.append(element("h3", label(39)), element("pre", node.definition.source, "forth"));
      panel.append(code);
    }
    for (const direction of [23, 24]) {
      const ports = node.ports.filter(port => port.direction === direction);
      const section = element("section", undefined, "details ports");
      section.append(element("h3", label(direction) + " (" + ports.length + ")"));
      for (const port of ports) {
        const detail = element("details");
        detail.open = true;
        detail.append(element("summary", port.name, "mono"));
        const values = element("dl");
        const peer = element("button", port.peer + " · " + port.peerPort, "peer");
        peer.addEventListener("click", () => {
          activeNode = port.peerId;
          renderGraph(true);
          renderInspector();
        });
        const destination = element("dd");
        destination.append(peer);
        values.append(element("dt", label(direction === 23 ? 30 : 31)), destination);
        for (const [key, value] of port.facts) {
          values.append(element("dt", label(key)), element("dd", value, key === 34 ? "mono outpoint" : ""));
        }
        detail.append(values);
        section.append(detail);
      }
      panel.append(section);
    }
  } else if (row.assertions?.length) {
    panel.append(description(label(14), row.assertions.map(stage => {
      const role = row.stage_roles?.find(entry => entry.stage === stage.stage)?.role;
      return [stage.stage + (role ? " · " + role : ""),
        [stage.backend, stage.transaction + " vin " + stage.vin, stage.authorizer, stage.policy].join(" · ")];
    })));
  }
  const actions = element("div", undefined, "actions");
  actions.append(download(label(15), "plan.json", pkg.plan), download(label(16), "receipt.json", pkg.receipt),
    download(label(17), "report.json", model.report, "link"));
  panel.append(actions);
  if (row.eligible && !pkg.plan) panel.append(element("p", label(26), "hint"));
}

function renderCandidates() {
  const query = $("search").value.trim().toLowerCase();
  const results = model.candidates.filter(row => row.id.toLowerCase().includes(query) &&
    (filter === "all" || (filter === "eligible") === row.eligible));
  const priority = row => row.id === model.selected ? 2 : model.packages[row.id]?.receipt ? 1 : 0;
  results.sort((left, right) => priority(right) - priority(left));
  const list = $("candidates");
  list.replaceChildren();
  if (!results.length) list.append(element("li", label(18), "empty"));
  for (const row of results) {
    const item = element("li");
    const button = element("button", undefined, "candidate");
    button.setAttribute("aria-pressed", row.id === selected);
    const meta = element("small");
    const pkg = model.packages[row.id];
    meta.append(element("span", label(pkg?.receipt ? 4 : row.eligible ? 2 : 3), "badge" + (row.eligible ? " available" : "")),
      element("span", bytes(pkg?.bytes ?? row.cost?.whole_path_bytes), "mono"));
    button.append(element("strong", row.id), meta);
    button.addEventListener("click", () => {
      selected = row.id;
      activeNode = null;
      renderCandidates();
      list.querySelector('[aria-pressed="true"]')?.focus();
      renderGraph();
      renderInspector();
    });
    item.append(button);
    list.append(item);
  }
}

function segments(id, options, current, choose) {
  const parent = $(id);
  parent.replaceChildren();
  for (const [key, name] of options) {
    const button = element("button", label(name));
    button.setAttribute("aria-pressed", key === current);
    button.addEventListener("click", () => {
      choose(key);
      parent.querySelector('[aria-pressed="true"]')?.focus();
    });
    parent.append(button);
  }
}

function render() {
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  for (const [id, value] of [["heading", 0], ["rail-title", 1], ["diagram-title", 7], ["port-hint", 22]]) {
    $(id).textContent = label(value);
  }
  const contexts = {bip143: "BIP143 ALL", otda: "Chronicle OTDA ALL", both: "BIP143 / OTDA ALL"};
  $("context").textContent = model.title + " · " + (contexts[model.sighash] ?? model.sighash) + " · " +
    label(28) + " " + model.current;
  $("search").placeholder = label(6);
  $("search").setAttribute("aria-label", label(6));
  $("stats").replaceChildren(...[
    [1, model.candidates.length], [2, model.candidates.filter(row => row.eligible).length],
    [4, Object.values(model.packages).filter(pkg => pkg.receipt).length],
  ].map(([name, count]) => {
    const stat = element("div");
    stat.append(element("dt", label(name)), element("dd", count));
    return stat;
  }));
  segments("filters", [["all", 5], ["eligible", 2], ["excluded", 3]], filter, key => { filter = key; render(); });
  segments("views", [["logical", 8], ["physical", 9]], view, key => { activeNode = null; view = key; render(); });
  for (const button of document.querySelectorAll("[data-lang]")) button.setAttribute("aria-pressed", button.dataset.lang === lang);
  renderCandidates();
  renderGraph();
  renderInspector();
}

for (const button of document.querySelectorAll("[data-lang]")) {
  button.addEventListener("click", () => { lang = button.dataset.lang; render(); });
}
$("search").addEventListener("input", renderCandidates);
render();
