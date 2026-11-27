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
  "Draft", "Draft model · not compiled or deployed", "Add Place", "Add Transition", "Import JSON", "Export JSON",
  "Name", "Token type", "Initial tokens", "Capacity", "Forth word", "Save node", "Delete node",
  "Add connection", "Port name", "Place", "Count", "Connect", "Delete", "Node metadata (JSON object)",
  "Import failed", "Name must be unique and nonempty.", "Select a node to edit.", "Inputs or outputs must reference a Place.",
  "Metadata is descriptive and has not been checked.", "Initial marking", "Select a Place", "New draft",
  "Incomplete models can be saved. Run the CPN checker before use.",
  "Visibility", "State carrier", "Forth code", "Constraints", "Signature roles", "External witnesses",
  "Evidence", "Proof policy", "Recursive requirements", "Add item", "Remove item", "Advanced metadata JSON",
  "Declarations are draft data and are not yet linked to generated transaction checks.",
  "The structured field and JSON were changed differently", "Structured item must be a JSON object.",
  "Design a CPN", "Model nodes", "No matching nodes.",
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
  "草稿", "模型草稿 · 尚未编译或部署", "添加 Place", "添加 Transition", "导入 JSON", "导出 JSON",
  "名称", "令牌类型", "初始令牌数", "容量", "Forth 词", "保存节点", "删除节点",
  "添加连接", "端口名称", "Place", "数量", "连接", "删除", "节点元信息（JSON 对象）",
  "导入失败", "名称必须非空且不重复。", "选择节点以编辑。", "输入或输出需要关联 Place。",
  "元信息仅用于描述，尚未验证。", "初始标记", "选择 Place", "新建草稿",
  "未完成的模型也可以保存，使用前请运行 CPN 检查器。",
  "可见性", "状态载体", "Forth 代码", "约束", "签名角色", "外部见证",
  "证明证据", "证明策略", "递归要求", "添加条目", "移除条目", "高级元信息 JSON",
  "这些声明是草稿数据，尚未连接到生成的交易检查。",
  "结构化字段和 JSON 的修改不一致", "结构化条目必须是 JSON 对象。",
  "设计 CPN", "模型节点", "没有符合条件的节点。",
];
let lang = "en";
let filter = "all";
let view = model.editor_start ? "draft" : "logical";
let selected = model.selected ?? model.candidates[0]?.id ?? null;
let activeNode = null;
let draft = model.draft ?? {schema_version: 1, places: [], transitions: []};
let draftError = "";
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
  if (view === "draft") {
    for (const place of draft.places) node("draft:place:" + place.name, place.name, "place", place.type);
    for (const transition of draft.transitions) {
      node("draft:transition:" + transition.name, transition.name, "transition", transition.word || "Transition");
      for (const port of transition.inputs) {
        link("draft:place:" + port.place, transition.name + " · " + port.name,
          "draft:transition:" + transition.name, port.name, [[37, port.type]]);
      }
      for (const port of transition.outputs) {
        link("draft:transition:" + transition.name, port.name, "draft:place:" + port.place,
          transition.name + " · " + port.name, [[37, port.type]]);
      }
    }
    return {nodes, edges};
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
  if (queue.length !== nodes.size) {
    // CPN cycles are logical recurrence. Arrange all nodes on a ring so each
    // edge remains inspectable without pretending the graph is acyclic.
    const ordered = [...nodes.values()];
    const width = Math.max(700, ordered.length * 100);
    const height = Math.max(440, ordered.length * 46);
    ordered.forEach((node, index) => {
      const angle = 2 * Math.PI * index / ordered.length - Math.PI / 2;
      node.height = Math.max(node.kind === "place" ? 58 : 73,
        26 + 17 * Math.max(node.inputs.length, node.outputs.length));
      node.x = width / 2 + (width / 2 - 110) * Math.cos(angle) - 68;
      node.y = height / 2 + (height / 2 - 65) * Math.sin(angle) - node.height / 2;
    });
    return {width, height, nodes: ordered, edges};
  }
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
    canvas.replaceChildren(element("p", label(view === "draft" ? 82 : 19), "empty"));
    return;
  }
  const {width, height, nodes, edges} = geometry;
  const plot = svg("svg", {viewBox: "0 0 " + width + " " + height, "aria-label": label(7)});
  plot.style.minWidth = Math.max(590, width) + "px";
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

function draftItem() {
  if (!activeNode?.startsWith("draft:")) return null;
  const [, kind, ...parts] = activeNode.split(":");
  return draft[kind === "place" ? "places" : "transitions"].find(item => item.name === parts.join(":")) ?? null;
}

function uniqueDraftName(kind) {
  const collection = kind === "place" ? draft.places : draft.transitions;
  let index = 1;
  while (collection.some(item => item.name === kind + index)) index++;
  return kind + index;
}

function checkDraft(document) {
  if (!document || document.schema_version !== 1 || !Array.isArray(document.places) || !Array.isArray(document.transitions)) {
    throw new Error("Expected schema_version 1 with places and transitions arrays.");
  }
  if (Object.keys(document).some(key => !["schema_version", "places", "transitions"].includes(key))) {
    throw new Error("Unknown model field.");
  }
  const isObject = value => value && typeof value === "object" && !Array.isArray(value);
  const name = value => typeof value === "string" && value.trim().length > 0;
  const integer = value => Number.isSafeInteger(value) && value >= 0;
  const noExtra = (object, keys) => Object.keys(object).every(key => keys.includes(key));
  const places = new Map();
  for (const place of document.places) {
    if (!isObject(place) || !noExtra(place, ["name", "type", "initial", "capacity", "metadata"]) ||
        !name(place.name) || !name(place.type) || places.has(place.name) ||
        (place.initial !== undefined && !integer(place.initial)) ||
        (place.capacity != null && !integer(place.capacity)) ||
        (place.metadata !== undefined && !isObject(place.metadata))) throw new Error("Invalid Place.");
    places.set(place.name, place);
  }
  const names = new Set();
  for (const transition of document.transitions) {
    if (!isObject(transition) || !noExtra(transition, ["name", "word", "inputs", "outputs", "metadata"]) ||
        !name(transition.name) || names.has(transition.name) ||
        (transition.word != null && !name(transition.word)) ||
        !Array.isArray(transition.inputs) || !Array.isArray(transition.outputs) ||
        (transition.metadata !== undefined && !isObject(transition.metadata))) throw new Error("Invalid Transition.");
    names.add(transition.name);
    for (const ports of [transition.inputs, transition.outputs]) {
      const usedNames = new Set(), usedPlaces = new Set();
      for (const port of ports) {
        if (!isObject(port) || !noExtra(port, ["name", "place", "type", "count"]) || !name(port.name) ||
            !places.has(port.place) || port.type !== places.get(port.place).type ||
            usedNames.has(port.name) || usedPlaces.has(port.place) ||
            (port.count !== undefined && (!integer(port.count) || port.count === 0))) throw new Error("Invalid connection.");
        usedNames.add(port.name);
        usedPlaces.add(port.place);
      }
    }
  }
  return document;
}

function field(form, name, value, type = "text") {
  const wrap = element("label", name);
  const input = element("input");
  input.type = type;
  input.value = value ?? "";
  if (type === "number") { input.min = "0"; input.step = "1"; }
  wrap.append(input);
  form.append(wrap);
  return input;
}

function textArea(form, name, value) {
  const wrap = element("label", name);
  const input = element("textarea");
  input.rows = 3;
  input.value = value ?? "";
  wrap.append(input);
  form.append(wrap);
  return input;
}

function metadataList(form, title, values) {
  const section = element("fieldset", undefined, "draft-list");
  section.append(element("legend", title));
  const rows = element("div");
  section.append(rows);
  const append = value => {
    const row = element("div", undefined, "draft-list-row");
    const structured = typeof value === "object";
    const input = element("textarea");
    input.value = structured ? JSON.stringify(value, null, 2) : value;
    input.setAttribute("aria-label", title);
    input.dataset.structured = structured ? "true" : "false";
    input.rows = structured ? 3 : 2;
    row.append(input, draftButton(label(99), () => row.remove()));
    rows.append(row);
  };
  if (Array.isArray(values)) values.forEach(append);
  section.append(draftButton(label(98), () => append("")));
  form.append(section);
  return () => [...rows.querySelectorAll("input, textarea")].map(input => {
    if (input.dataset.structured === "true") {
      const object = JSON.parse(input.value);
      if (!object || typeof object !== "object" || Array.isArray(object)) throw new Error(label(103));
      return object;
    }
    if (!input.value.trim()) throw new Error(title);
    return input.value;
  });
}

function mergeDraftMetadata(raw, original, changes) {
  const result = JSON.parse(raw);
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error(label(79));
  for (const [key, next, before] of changes) {
    const serialized = JSON.stringify;
    if (serialized(next) === serialized(before)) continue;
    if (serialized(result[key]) !== serialized(original[key]) && serialized(result[key]) !== serialized(next)) {
      throw new Error(label(102) + ": " + key);
    }
    if (next === "") delete result[key];
    else result[key] = next;
  }
  return result;
}

function draftButton(text, action) {
  const button = element("button", text);
  button.type = "button";
  button.addEventListener("click", action);
  return button;
}

function setDraftNode(kind) {
  const name = uniqueDraftName(kind);
  if (kind === "place") draft.places.push({name, type: "u32", initial: 0, capacity: null, metadata: {}});
  else draft.transitions.push({name, word: null, inputs: [], outputs: [], metadata: {}});
  activeNode = "draft:" + kind + ":" + name;
  draftError = "";
  render();
}

function draftTools() {
  const tools = $("draft-tools");
  tools.hidden = view !== "draft";
  tools.replaceChildren();
  if (tools.hidden) return;
  const note = element("span", label(61) + " · " + label(88), "draft-note");
  tools.append(note, draftButton(label(62), () => setDraftNode("place")),
    draftButton(label(63), () => setDraftNode("transition")));
  const input = element("input");
  input.type = "file";
  input.accept = "application/json,.json";
  input.hidden = true;
  input.addEventListener("change", async () => {
    if (!input.files.length) return;
    try {
      if (input.files[0].size > 5_000_000) throw new Error("File exceeds 5 MB.");
      draft = checkDraft(JSON.parse(await input.files[0].text()));
      draftError = "";
      activeNode = null;
    } catch (error) {
      draftError = label(80) + ": " + error.message;
    }
    render();
  });
  tools.append(input, draftButton(label(64), () => input.click()),
    download(label(65), "cpn-draft.json", draft));
}

function draftInspector(panel) {
  panel.replaceChildren(element("h2", label(60)), element("p", label(61), "draft-note"));
  if (draftError) panel.append(element("p", draftError, "draft-error"));
  const item = draftItem();
  if (!item) {
    panel.append(element("p", label(82), "hint"));
    return;
  }
  const isPlace = draft.places.includes(item);
  const form = element("form", undefined, "draft-form");
  const name = field(form, label(66), item.name);
  name.required = true;
  const tokenType = isPlace ? field(form, label(67), item.type) : null;
  if (tokenType) tokenType.required = true;
  const initial = isPlace ? field(form, label(68), item.initial ?? 0, "number") : null;
  const capacity = isPlace ? field(form, label(69), item.capacity, "number") : null;
  const word = !isPlace ? field(form, label(70), item.word) : null;
  const original = item.metadata ?? {};
  const edits = [];
  const textEdit = (key, title, multiline = false) => {
    const before = typeof original[key] === "string" ? original[key] : "";
    const input = multiline ? textArea(form, title, before) : field(form, title, before);
    edits.push(() => [key, input.value, before]);
  };
  const listEdit = (key, title) => {
    const before = Array.isArray(original[key]) ? original[key] : [];
    const read = metadataList(form, title, before);
    edits.push(() => [key, read(), before]);
  };
  if (isPlace) {
    textEdit("visibility", label(89));
    textEdit("carrier", label(90));
  } else {
    textEdit("forth_source", label(91), true);
    listEdit("constraints", label(92));
    listEdit("authorization", label(93));
    listEdit("witnesses", label(94));
    listEdit("evidence", label(95));
    textEdit("recursive_requirements", label(97), true);
  }
  const policyBefore = !isPlace && Array.isArray(original.evidence)
    ? original.evidence.find(entry => entry && typeof entry === "object" && typeof entry.policy === "string")?.policy ?? ""
    : "";
  const policy = !isPlace ? field(form, label(96), policyBefore) : null;
  const metadataLabel = element("label", label(79));
  const metadata = element("textarea");
  metadata.rows = 5;
  metadata.value = JSON.stringify(original, null, 2);
  metadataLabel.append(metadata);
  const advanced = element("details", undefined, "draft-advanced");
  advanced.append(element("summary", label(100)), metadataLabel);
  form.append(advanced, element("small", label(101), "hint"));
  const errorMessage = element("p", "", "draft-error");
  errorMessage.setAttribute("role", "alert");
  form.append(errorMessage);
  const submit = element("button", label(71));
  submit.type = "submit";
  form.append(submit);
  form.addEventListener("submit", event => {
    event.preventDefault();
    try {
      const value = mergeDraftMetadata(metadata.value, original, edits.map(read => read()));
      if (policy && policy.value !== policyBefore) {
        if (value.evidence !== undefined && !Array.isArray(value.evidence)) throw new Error(label(95));
        const evidence = value.evidence ?? [];
        const index = evidence.findIndex(entry => entry && typeof entry === "object" &&
          !Array.isArray(entry) && typeof entry.policy === "string");
        if (index >= 0) {
          const entry = {...evidence[index]};
          if (policy.value.trim()) entry.policy = policy.value.trim();
          else delete entry.policy;
          if (Object.keys(entry).length) evidence[index] = entry;
          else evidence.splice(index, 1);
        } else if (policy.value.trim()) evidence.push({policy: policy.value.trim()});
        if (evidence.length || value.evidence !== undefined) value.evidence = evidence;
      }
      const nextName = name.value.trim();
      const collection = isPlace ? draft.places : draft.transitions;
      if (!nextName || collection.some(other => other !== item && other.name === nextName)) throw new Error(label(81));
      if (isPlace) {
        const nextType = tokenType.value.trim();
        const nextInitial = Number(initial.value), nextCapacity = capacity.value === "" ? null : Number(capacity.value);
        if (!nextType || !Number.isSafeInteger(nextInitial) || nextInitial < 0 ||
            (nextCapacity !== null && (!Number.isSafeInteger(nextCapacity) || nextCapacity < nextInitial))) {
          throw new Error(label(67));
        }
        for (const transition of draft.transitions) for (const port of [...transition.inputs, ...transition.outputs]) {
          if (port.place === item.name) { port.place = nextName; port.type = nextType; }
        }
        item.type = nextType;
        item.initial = nextInitial;
        item.capacity = nextCapacity;
      } else item.word = word.value.trim() || null;
      item.metadata = value;
      item.name = nextName;
      activeNode = "draft:" + (isPlace ? "place:" : "transition:") + nextName;
      draftError = "";
      render();
    } catch (error) {
      draftError = error.message;
      errorMessage.textContent = error.message;
    }
  });
  panel.append(form);
  panel.append(draftButton(label(72), () => {
    if (isPlace) {
      draft.places = draft.places.filter(place => place !== item);
      for (const transition of draft.transitions) {
        transition.inputs = transition.inputs.filter(port => port.place !== item.name);
        transition.outputs = transition.outputs.filter(port => port.place !== item.name);
      }
    } else draft.transitions = draft.transitions.filter(transition => transition !== item);
    activeNode = null;
    draftError = "";
    render();
  }));
  if (!isPlace) {
    for (const [key, heading] of [["inputs", 23], ["outputs", 24]]) {
      const section = element("section", undefined, "details");
      section.append(element("h3", label(heading)));
      const list = element("ul", undefined, "draft-edges");
      for (const port of item[key]) {
        const row = element("li");
        row.append(element("span", port.name + " → " + port.place + " · " + port.type + " × " + (port.count ?? 1)),
          draftButton(label(78), () => {
            item[key] = item[key].filter(other => other !== port);
            render();
          }));
        list.append(row);
      }
      section.append(list);
      const connect = element("form", undefined, "draft-form");
      const port = field(connect, label(74), "");
      port.required = true;
      const placeLabel = element("label", label(75));
      const place = element("select");
      place.setAttribute("aria-label", label(75));
      const placeholder = element("option", label(86));
      placeholder.value = "";
      place.append(placeholder);
      for (const entry of draft.places) {
        const option = element("option", entry.name + " · " + entry.type);
        option.value = entry.name;
        place.append(option);
      }
      placeLabel.append(place);
      connect.append(placeLabel);
      const count = field(connect, label(76), "1", "number");
      count.min = "1";
      const button = element("button", label(73) + " · " + label(heading));
      button.type = "submit";
      connect.append(button);
      connect.addEventListener("submit", event => {
        event.preventDefault();
        const destination = draft.places.find(entry => entry.name === place.value);
        const portName = port.value.trim(), quantity = Number(count.value);
        if (!destination || !portName || !Number.isSafeInteger(quantity) || quantity < 1 ||
            item[key].some(entry => entry.name === portName || entry.place === destination.name)) {
          draftError = label(83);
          draftInspector(panel);
          return;
        }
        item[key].push({name: portName, place: destination.name, type: destination.type, count: quantity});
        draftError = "";
        render();
      });
      section.append(connect);
      panel.append(section);
    }
  }
}

function renderInspector() {
  if (view === "draft") { draftInspector($("inspector")); return; }
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
  if (view === "draft") {
    const list = $("candidates");
    list.replaceChildren();
    const items = [
      ...draft.places.map(item => ({kind: "place", item})),
      ...draft.transitions.map(item => ({kind: "transition", item})),
    ].filter(({item}) => item.name.toLowerCase().includes(query));
    if (!items.length) list.append(element("li", label(106), "empty"));
    for (const {kind, item} of items) {
      const li = element("li"), button = element("button", undefined, "candidate");
      const identity = "draft:" + kind + ":" + item.name;
      button.setAttribute("aria-pressed", identity === activeNode);
      button.append(element("strong", item.name), element("small", kind === "place" ? "Place · " + item.type : "Transition"));
      button.addEventListener("click", () => {
        activeNode = identity;
        renderCandidates();
        renderGraph();
        renderInspector();
      });
      li.append(button);
      list.append(li);
    }
    return;
  }
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
  if (view === "draft") {
    $("heading").textContent = label(104);
    $("rail-title").textContent = label(105);
  }
  $("stats").hidden = view === "draft";
  $("filters").hidden = view === "draft";
  const contexts = {bip143: "BIP143 ALL", otda: "Chronicle OTDA ALL", both: "BIP143 / OTDA ALL"};
  $("context").textContent = model.editor_start ? label(61) :
    model.title + " · " + (contexts[model.sighash] ?? model.sighash) + " · " + label(28) + " " + model.current;
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
  const choices = model.editor_start ? [["draft", 60]] : [["logical", 8], ["physical", 9], ["draft", 60]];
  segments("views", choices, view, key => { activeNode = null; view = key; render(); });
  draftTools();
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
