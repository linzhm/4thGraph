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
  "Recorded replay", "Recorded transactions; chain state is not live.", "Previous", "Next", "Reset",
  "Before deployment", "Step", "Consumed", "Produced", "Transaction ID", "Recorded block height",
  "Graph and recorded outpoint differ", "Funding input", "Recorded transaction bytes",
  "Fixture snapshot", "Provided parents only · chain admission and UTXO status not established",
  "Copy to draft", "Return to snapshot", "Copied draft · no verification applies to edits",
  "Recorded BSV Node Script verdicts", "chain-gang rechecked at export", "Passed", "Rejected", "Not run",
  "Transaction", "Token quantity", "Owner public key", "Fixture model metadata", "Download fixture model",
  "Resume draft", "Input", "Output", "Download verification bundle",
  "Declared", "Built", "Recorded replay", "Unavailable", "Assertion", "Proof", "Recursion", "State",
  "Declared requirements · not compiled", "Compiled stage", "Proof backend", "Statement digest",
  "Verification key digest", "Recursion statement · verifier unavailable", "Public inputs", "Base requirements",
  "Step requirements", "Backend is unavailable", "Carrier", "Evidence requirements",
  "Recursive statement",
  "Advanced metadata JSON also supports extension fields.",
  "Recursion ports", "Previous proof input", "Previous state input", "Next state output",
  "Origin field", "Base-case transition", "Unresolved reference", "Leave fields blank to remove the declaration.",
  "Select a port", "Select a transition", "Declaration only · proof and origin binding are not verified.",
  "Transaction layout requirements", "Atomic with", "Independent submission",
  "The compiler checks whether these requirements can be satisfied.",
  "Edit the malformed requirement in Advanced metadata JSON.", "No other transitions",
  "A transition cannot be atomic with itself", "Unknown transition",
  "Compile and inspect", "Close build guide", "Local build steps",
  "Save node edits and download the current model as cpn-draft.json into your working directory.",
  "Replace the example filenames and current value. words.fth must define the referenced Forth words and its imports; keys.json must contain the required public-key roles. Forth code recorded in node metadata remains draft data.",
  "workflow.fth must be a new file in the same directory as words.fth. The compiler currently accepts supported two- or three-stage linear models; other models return diagnostics.",
  "Run these steps in a terminal. Continue only when the preceding step succeeds. The browser does not compile or verify this model.",
  "Check the model", "Explore candidates", "Verify model and workflow", "Open the report",
  "Copy", "Copied", "Copy failed. Select the command and copy it manually.",
  "verify-model checks lowering provenance. Proofs, transaction execution, and chain state require separate verification.",
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
  "已记录复放", "展示已记录交易，链状态非实时。", "上一步", "下一步", "重置",
  "部署前", "步骤", "消耗", "生成", "交易 ID", "记录的区块高度",
  "图与记录的 outpoint 不一致", "入金输入", "记录的交易字节",
  "夹具快照", "仅验证给定父交易 · 未确认入池、入块或 UTXO 状态",
  "复制为草稿", "返回快照", "已复制为草稿 · 编辑后无验证结果",
  "已记录的 BSV Node Script 结果", "导出时重新验证的 chain-gang 结果", "通过", "拒绝", "未运行",
  "交易", "代币数量", "持有人公钥", "夹具模型元信息", "下载夹具模型",
  "继续编辑草稿", "输入", "输出", "下载验证包",
  "已声明", "已构建", "已记录复放", "不可用", "断言", "证明", "递归", "状态",
  "声明的要求 · 尚未编译", "已编译阶段", "证明后端", "声明摘要",
  "验证密钥摘要", "递归声明 · 验证器尚不可用", "公开输入", "初始条件",
  "递归步条件", "后端不可用", "载体", "证明要求",
  "递归声明",
  "高级元信息 JSON 也可编辑扩展字段。",
  "递归端口", "前序证明输入", "前序状态输入", "新状态输出",
  "发行根字段", "基础迁移", "引用未解析", "清空字段可移除该声明。",
  "选择端口", "选择迁移", "仅声明 · 前序证明及发行根绑定尚未验证。",
  "交易布局要求", "与以下迁移原子执行", "独立提交",
  "编译器会检查这些要求能否同时满足。",
  "请在高级元信息 JSON 中修正格式错误的要求。", "没有其他迁移",
  "迁移不能与自身声明原子执行", "未知迁移",
  "编译与查看", "收起构建指南", "本机构建步骤",
  "先保存节点修改，将当前模型下载为 cpn-draft.json 并放入工作目录。",
  "将示例文件名和初始值换成实际值。words.fth 需定义所引用的 Forth 词及其导入，keys.json 需包含所需角色的公钥。节点元信息中的 Forth 代码仍是草稿数据。",
  "workflow.fth 必须是与 words.fth 同目录的新文件。编译器目前接受受支持的两阶段或三阶段线性模型，其他模型会返回诊断。",
  "在终端依次运行下列步骤，上一步成功后再继续。浏览器不会编译或验证此模型。",
  "检查模型", "探索候选", "核对模型与工作流", "打开报告",
  "复制", "已复制", "复制失败，请选中命令后手动复制。",
  "verify-model 核对降级来源。证明、交易执行及链状态需要分别验证。",
];
let lang = "en";
let filter = "all";
let view = model.fixture_mode ? "fixture" : model.editor_start ? "draft" : "logical";
let selected = model.selected ?? model.candidates[0]?.id ?? null;
let activeNode = null;
const fixtureGraph = model.fixture_mode ? JSON.parse(JSON.stringify(model.draft)) : null;
let draft = model.fixture_mode ? {schema_version: 1, places: [], transitions: []} :
  model.draft ?? {schema_version: 1, places: [], transitions: []};
let fixtureCopied = false;
let draftError = "";
let replayIndex = -1;
let buildGuideOpen = false;
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
  if (view === "draft" || view === "fixture") {
    const net = view === "fixture" ? fixtureGraph : draft;
    for (const place of net.places) {
      const current = nodes.get(node(view + ":place:" + place.name, place.name, "place", place.type));
      if (place.metadata?.carrier || place.metadata?.visibility) current.tags = [label(147)];
      if (current.tags && view === "draft") current.tags.push(label(140));
    }
    for (const transition of net.transitions) {
      const current = nodes.get(node(view + ":transition:" + transition.name, transition.name, "transition",
        transition.word || "Transition"));
      const meta = transition.metadata ?? {};
      const tags = [];
      if (Array.isArray(meta.constraints) && meta.constraints.length) tags.push(label(144));
      if (Array.isArray(meta.evidence) && meta.evidence.length) tags.push(label(145));
      if (meta.recursive_requirements || meta.recursion) tags.push(label(146));
      if (tags.length) current.tags = [...tags, label(140)];
      for (const port of transition.inputs) {
        link(view + ":place:" + port.place, transition.name + " · " + port.name,
          view + ":transition:" + transition.name, port.name, [[37, port.type]]);
      }
      for (const port of transition.outputs) {
        link(view + ":transition:" + transition.name, port.name, view + ":place:" + port.place,
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
      if (related.length) transition.tags = [label(144),
        ...(related.some(stage => stage.backend !== "script") ? [label(145)] : []),
        label(recorded ? 142 : 141)];
      for (const out of row.outputs) {
        const output = nodes.get(node(place(row.step, out.vout), out.place, "place", out.kind, out.spendable));
        output.facts = [[41, label(out.spendable ? 56 : 57)]];
        if (out.kind === "state" || out.kind === "receipt") output.tags = [label(147), label(recorded ? 142 : 141)];
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
      nodes.get(id).tags = [label(144), ...(proof ? [label(145)] : []),
        label(model.packages[selected]?.receipt ? 142 : 141)];
      nodes.get(id).proof = proof;
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
      const evidence = nodes.get(node("proof:" + item.id, item.id, "transition", item.backend));
      evidence.tags = [label(145), label(143)];
      evidence.facts = [[159, item.proves], [157, item.backend]];
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
      node.height = Math.max(node.tags?.length > 3 ? 112 : node.tags?.length ? 99 : node.kind === "place" ? 58 : 73,
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
    node.height = Math.max(node.tags?.length > 3 ? 112 : node.tags?.length ? 99 : node.kind === "place" ? 58 : 73,
      26 + 17 * Math.max(node.inputs.length, node.outputs.length));
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

function currentReplay() {
  if (view !== "physical") return null;
  const pkg = model.packages[selected];
  const graph = byId.get(selected)?.graph;
  if (!pkg?.receipt || !graph || !Array.isArray(pkg.receipt.spends)) return null;
  const rows = [{...pkg.receipt.deployment, step: "deploy"}, ...pkg.receipt.spends];
  if (replayIndex < 0 || replayIndex >= rows.length) return {rows};
  const row = rows[replayIndex];
  const template = graph.transactions.find(item => item.step === row.step);
  if (!template || !pkg.transactions?.[row.step]) return {rows, row, invalid: true};
  const record = pkg.transactions[row.step];
  const consumed = (row.previous ?? []).map((outpoint, vin) => {
    const source = template.inputs[vin]?.from;
    const actual = source && pkg.transactions[source.step]?.outputs[source.vout]?.outpoint;
    return {outpoint, vin, place: source && actual === outpoint ? "utxo:" + source.step + ":" + source.vout : null,
      mismatch: source ? actual !== outpoint : row.step !== "deploy"};
  });
  const produced = (record.outputs ?? []).map((output, slot) => {
    const port = template.outputs[slot];
    const expected = row.txid + ":" + slot;
    return {outpoint: output.outpoint, slot,
      place: port && output.outpoint === expected ? "utxo:" + row.step + ":" + port.vout : null,
      mismatch: !port || port.vout !== slot || output.outpoint !== expected};
  });
  return {rows, row, consumed, produced, invalid: row.step !== "deploy" && template.inputs.length !== consumed.length ||
    template.outputs.length !== produced.length};
}

function renderReplay() {
  const container = $("replay");
  const state = currentReplay();
  container.hidden = state === null;
  container.replaceChildren();
  if (!state) return;
  const header = element("div", undefined, "replay-header");
  const title = element("div");
  title.append(element("h3", label(107)), element("p", label(108), "hint"));
  const controls = element("div", undefined, "replay-controls");
  const previous = draftButton(label(109), () => { replayIndex--; activeNode = null; render(); });
  previous.disabled = replayIndex < 0;
  const next = draftButton(label(110), () => { replayIndex++; activeNode = null; render(); });
  next.disabled = replayIndex >= state.rows.length - 1;
  const reset = draftButton(label(111), () => { replayIndex = -1; activeNode = null; render(); });
  reset.disabled = replayIndex < 0;
  controls.append(previous, next, reset);
  header.append(title, controls);
  container.append(header);
  if (!state.row) {
    container.append(element("p", label(112), "replay-step"));
    return;
  }
  const row = state.row;
  container.append(element("p", label(113) + " " + (replayIndex + 1) + " / " + state.rows.length + " · " + row.step, "replay-step"));
  const facts = element("dl", undefined, "replay-facts");
  const height = row.bsv_node?.height;
  for (const [name, value] of [[116, row.txid], [117, height], [120, row.bytes == null ? null : bytes(row.bytes)]]) {
    if (value === null || value === undefined) continue;
    facts.append(element("dt", label(name)), element("dd", value, name === 116 ? "mono outpoint" : ""));
  }
  container.append(facts);
  if (state.invalid) container.append(element("p", label(118), "draft-error"));
  for (const [heading, entries] of [[114, state.consumed ?? []], [115, state.produced ?? []]]) {
    const section = element("div", undefined, "replay-places");
    section.append(element("strong", label(heading)));
    const list = element("ul");
    for (const entry of entries) {
      const item = element("li");
      const prefix = heading === 114 ? "vin " + entry.vin : "vout " + entry.slot;
      if (entry.place) {
        const button = draftButton(prefix + " · " + entry.outpoint, () => {
          activeNode = entry.place;
          renderGraph(true);
          renderInspector();
        });
        item.append(button);
      } else {
        item.append(element("span", prefix + " · " + entry.outpoint, "mono outpoint"));
        if (entry.mismatch) item.append(element("small", label(118), "draft-error"));
        else if (heading === 114 && row.step === "deploy") item.append(element("small", label(119), "hint"));
      }
      list.append(item);
    }
    if (!entries.length) list.append(element("li", "—"));
    section.append(list);
    container.append(section);
  }
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
  const replay = currentReplay();
  const consumed = new Set(replay?.consumed?.map(item => item.place).filter(Boolean) ?? []);
  const produced = new Set(replay?.produced?.map(item => item.place).filter(Boolean) ?? []);
  for (const node of nodes) {
    const event = node.id === "tx:" + replay?.row?.step ? " replay-current" :
      consumed.has(node.id) ? " replay-consumed" : produced.has(node.id) ? " replay-produced" : "";
    const group = svg("g", {class: "node " + node.kind + (node.spendable ? "" : " unspendable") + event,
      role: "button", tabindex: 0, "aria-label": node.kind + " " + node.title, "aria-pressed": node.id === activeNode});
    group.append(svg("rect", {x: node.x, y: node.y, width: boxWidth, height: node.height,
      rx: node.kind === "place" ? 26 : 7}));
    group.append(svg("title", {}, node.title + " · " + node.detail));
    const cx = node.x + boxWidth / 2;
    const outpoint = /^([0-9a-f]{64}):(\d+)$/i.exec(node.title);
    const shortTitle = outpoint ? outpoint[1].slice(0, 8) + "…:" + outpoint[2] :
      node.title.length > 16 ? node.title.slice(0, 15) + "…" : node.title;
    group.append(svg("text", {x: cx, y: node.y + 23, "text-anchor": "middle", class: "node-title"}, shortTitle));
    const detail = node.detail.length > 20 ? node.detail.slice(0, 19) + "…" : node.detail;
    group.append(svg("text", {x: cx, y: node.y + 42, "text-anchor": "middle", class: "node-detail"}, detail));
    if (node.tags?.length) {
      const statusLabels = [label(140), label(141), label(142), label(143)];
      const status = statusLabels.includes(node.tags[node.tags.length - 1]) ? node.tags[node.tags.length - 1] : "";
      const tags = node.tags.slice(0, status ? -1 : undefined);
      group.append(svg("text", {x: cx, y: node.y + 63, "text-anchor": "middle", class: "node-tags"},
        tags.slice(0, 2).join(" · ")));
      if (tags.length > 2) group.append(svg("text", {x: cx, y: node.y + 77, "text-anchor": "middle", class: "node-tags"},
        tags.slice(2).join(" · ")));
      if (status) group.append(svg("text", {x: cx, y: node.y + (tags.length > 2 ? 92 : 79),
        "text-anchor": "middle", class: "node-status"}, status));
    }
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

function declarations(metadata) {
  const fields = [
    ["visibility", 89], ["carrier", 158], ["constraints", 92], ["authorization", 93],
    ["witnesses", 94], ["evidence", 159], ["recursive_requirements", 97], ["recursion", 146],
    ["atomic_with", 174], ["independent_submit", 175],
  ];
  return fields.filter(([key]) => metadata?.[key] !== undefined).map(([key, name]) => {
    const value = metadata[key];
    return [label(name), typeof value === "string" ? value : JSON.stringify(value)];
  });
}

function recursionStatements(panel, candidate) {
  const report = model.report?.schedule_explanation ?? model.report;
  const statements = report?.recursive_statements ?? [];
  if (!statements.length) return;
  const unavailable = candidate.exclusions?.some(item => item.code === "recursive_backend_unavailable");
  for (const statement of statements) {
    panel.append(description(label(unavailable ? 153 : 160), [
      [statement.predicate, statement.edge],
      [label(154), statement.public_inputs?.join(" · ")],
      [label(155), statement.base?.join(" · ")],
      [label(156), statement.step?.join(" · ")],
      [label(151), statement.statement_sha256],
    ]));
  }
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

function recursionEditor(form, item, original) {
  const before = original.recursion;
  const value = before && typeof before === "object" && !Array.isArray(before) ? before : {};
  const group = element("details", undefined, "draft-advanced recursion-editor");
  group.open = Boolean(before);
  group.append(element("summary", label(162)), element("p", label(172), "hint"));
  const inputs = {};

  function select(key, title, values, placeholder) {
    const wrap = element("label", title);
    const input = element("select");
    input.setAttribute("aria-label", title);
    const empty = element("option", placeholder);
    empty.value = "";
    input.append(empty);
    const old = typeof value[key] === "string" ? value[key] : "";
    if (old && !values.includes(old)) {
      const missing = element("option", old + " · " + label(168));
      missing.value = old;
      input.append(missing);
    }
    for (const optionValue of values) {
      const option = element("option", optionValue);
      option.value = optionValue;
      input.append(option);
    }
    input.value = old;
    wrap.append(input);
    group.append(wrap);
    inputs[key] = input;
  }

  select("previous_proof", label(163), item.inputs.map(port => port.name), label(170));
  select("previous_state", label(164), item.inputs.map(port => port.name), label(170));
  select("next_state", label(165), item.outputs.map(port => port.name), label(170));
  inputs.origin_field = field(group, label(166), typeof value.origin_field === "string" ? value.origin_field : "");
  select("base_case", label(167), draft.transitions.map(transition => transition.name), label(171));
  group.append(element("p", label(169), "hint"));
  const feedback = element("p", "", "draft-error");
  feedback.setAttribute("role", "status");
  group.append(feedback);
  function showUnresolved() {
    const values = Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, input.value.trim()]));
    if (!Object.values(values).some(Boolean)) {
      feedback.textContent = "";
      return;
    }
    const available = {
      previous_proof: item.inputs.map(port => port.name),
      previous_state: item.inputs.map(port => port.name),
      next_state: item.outputs.map(port => port.name),
      base_case: draft.transitions.map(transition => transition.name),
    };
    const names = {previous_proof: 163, previous_state: 164, next_state: 165, origin_field: 166, base_case: 167};
    const missing = Object.keys(values).filter(key => !values[key] || available[key] && !available[key].includes(values[key]));
    feedback.textContent = missing.length ? label(168) + ": " + missing.map(key => label(names[key])).join(", ") : "";
  }
  group.addEventListener("input", showUnresolved);
  group.addEventListener("change", showUnresolved);
  showUnresolved();
  form.append(group);

  return () => {
    const values = Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, input.value.trim()]));
    const unchanged = Object.entries(values).every(([key, input]) =>
      input === (typeof value[key] === "string" ? value[key] : ""));
    if (unchanged) return ["recursion", before, before];
    const next = {...value};
    for (const [key, input] of Object.entries(values)) {
      if (input) next[key] = input;
      else delete next[key];
    }
    return ["recursion", Object.keys(next).length ? next : "", before];
  };
}

function transactionRequirements(form, item, original) {
  const group = element("fieldset", undefined, "draft-list");
  group.append(element("legend", label(173)), element("p", label(176), "hint"));
  const originalAtomic = original.atomic_with;
  const validAtomic = originalAtomic === undefined ||
    Array.isArray(originalAtomic) && originalAtomic.every(value => typeof value === "string" && value.trim());
  const before = validAtomic && Array.isArray(originalAtomic) ? originalAtomic : [];
  const currentNames = new Map(draft.transitions.map(transition => [transition.name.toLowerCase(), transition.name]));
  const choices = new Map();
  for (const reference of before) choices.set(reference.toLowerCase(), reference);
  for (const transition of draft.transitions) {
    const key = transition.name.toLowerCase();
    if (key !== item.name.toLowerCase() && !choices.has(key)) choices.set(key, transition.name);
  }
  const heading = element("strong", label(174));
  heading.style.display = "block";
  heading.style.fontSize = "13px";
  group.append(heading);
  const checks = [];
  for (const [key, reference] of choices) {
    const self = key === item.name.toLowerCase();
    const missing = !currentNames.has(key);
    const container = element("label");
    container.style.display = "flex";
    container.style.alignItems = "start";
    container.style.gap = "6px";
    const input = element("input");
    input.type = "checkbox";
    input.style.width = "auto";
    input.style.marginTop = "3px";
    input.checked = before.some(value => value.toLowerCase() === key);
    input.disabled = !validAtomic;
    const suffix = self ? label(179) : missing ? label(180) : "";
    const description = currentNames.get(key) ?? reference;
    container.append(input, element("span", suffix ? description + " · " + suffix : description));
    group.append(container);
    checks.push({key, reference, input, self, missing});
  }
  if (!choices.size) group.append(element("p", label(178), "hint"));
  const unresolved = element("p", "", "draft-error");
  unresolved.setAttribute("role", "status");
  const update = () => {
    const invalid = checks.filter(check => check.input.checked && (check.self || check.missing));
    unresolved.textContent = invalid.length ? label(168) + ": " + invalid.map(check => check.reference).join(", ") : "";
  };
  group.addEventListener("change", update);
  update();
  group.append(unresolved);
  const isBoolean = original.independent_submit === undefined || typeof original.independent_submit === "boolean";
  const separateLabel = element("label");
  separateLabel.style.display = "flex";
  separateLabel.style.alignItems = "start";
  separateLabel.style.gap = "6px";
  const separate = element("input");
  separate.type = "checkbox";
  separate.style.width = "auto";
  separate.style.marginTop = "3px";
  separate.checked = original.independent_submit === true;
  separate.disabled = !isBoolean;
  separateLabel.append(separate, element("span", label(175)));
  group.append(separateLabel);
  if (!validAtomic || !isBoolean) group.append(element("p", label(177), "draft-error"));
  form.append(group);

  return () => {
    let atomic = originalAtomic;
    if (validAtomic) {
      const enabled = new Set(checks.filter(check => check.input.checked).map(check => check.key));
      const selected = before.filter(reference => enabled.has(reference.toLowerCase()));
      for (const check of checks) {
        if (check.input.checked && !before.some(reference => reference.toLowerCase() === check.key)) {
          selected.push(check.reference);
        }
      }
      if (JSON.stringify(selected) !== JSON.stringify(before)) atomic = selected;
    }
    const independent = separate.checked === (original.independent_submit === true)
      ? original.independent_submit : separate.checked;
    return [["atomic_with", atomic, originalAtomic], ["independent_submit", independent, original.independent_submit]];
  };
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

async function copyCommand(command, status) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(command);
    status.textContent = label(193);
    return;
  } catch (_) {
    // Local file previews can lack the asynchronous clipboard API.
  }
  const input = element("textarea");
  input.value = command;
  input.style.position = "fixed";
  input.style.left = "-10000px";
  document.body.append(input);
  input.select();
  let copied = false;
  try { copied = document.execCommand("copy"); } catch (_) { /* Manual selection remains available. */ }
  input.remove();
  status.textContent = label(copied ? 193 : 194);
}

function draftBuildGuide() {
  const section = element("section", undefined, "build-guide");
  section.append(element("h3", label(183)));
  for (const index of [184, 185, 186, 187, 195]) section.append(element("p", label(index)));
  const steps = [
    [188, "4thgraph cpn check-model cpn-draft.json"],
    [189, "4thgraph cpn tune-model cpn-draft.json --source words.fth --output workflow.fth --keys keys.json --current 19 --target both > report.json"],
    [190, "4thgraph cpn verify-model cpn-draft.json --source words.fth --workflow workflow.fth --report report.json"],
    [191, "4thgraph cpn workbench report.json --source workflow.fth --output workbench.html"],
  ];
  const list = element("ol");
  for (const [name, command] of steps) {
    const item = element("li");
    const status = element("span", "", "copy-status");
    status.setAttribute("role", "status");
    const copy = draftButton(label(192), () => copyCommand(command, status));
    copy.setAttribute("aria-label", label(192) + " · " + label(name));
    const heading = element("div", undefined, "build-step");
    heading.append(element("strong", label(name)), copy, status);
    item.append(heading, element("pre", command, "build-command"));
    list.append(item);
  }
  section.append(list);
  return section;
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
  tools.hidden = view !== "draft" && view !== "fixture";
  tools.replaceChildren();
  if (tools.hidden) return;
  if (view === "fixture") {
    tools.append(element("span", label(122), "draft-note"), draftButton(label(fixtureCopied ? 136 : 123), () => {
      if (!fixtureCopied) {
        draft = JSON.parse(JSON.stringify(fixtureGraph));
        for (const item of [...draft.places, ...draft.transitions]) {
          if (!item.metadata) continue;
          for (const field of ["verified", "verification", "archive_validation", "node_verdicts", "chain_gang", "status"]) {
            delete item.metadata[field];
          }
        }
        fixtureCopied = true;
      }
      activeNode = null;
      view = "draft";
      render();
    }));
    return;
  }
  const note = element("span", label(61) + " · " + (model.fixture_mode ? label(125) : label(88)), "draft-note");
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
    download(label(65), "cpn-draft.json", draft),
    draftButton(label(buildGuideOpen ? 182 : 181), () => {
      buildGuideOpen = !buildGuideOpen;
      draftTools();
    }));
  if (buildGuideOpen) tools.append(draftBuildGuide());
}

function draftInspector(panel) {
  panel.replaceChildren(element("h2", label(60)), element("p", label(61), "draft-note"));
  if (draftError) panel.append(element("p", draftError, "draft-error"));
  const item = draftItem();
  if (!item) {
    panel.append(element("p", label(82), "hint"));
    return;
  }
  const declared = declarations(item.metadata);
  if (declared.length) panel.append(description(label(148), declared));
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
  let requirements;
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
    edits.push(recursionEditor(form, item, original));
    requirements = transactionRequirements(form, item, original);
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
  form.append(advanced);
  form.append(element("small", label(101), "hint"));
  const errorMessage = element("p", "", "draft-error");
  errorMessage.setAttribute("role", "alert");
  form.append(errorMessage);
  const submit = element("button", label(71));
  submit.type = "submit";
  form.append(submit);
  form.addEventListener("submit", event => {
    event.preventDefault();
    try {
      const changes = edits.map(read => read());
      if (requirements) changes.push(...requirements());
      const value = mergeDraftMetadata(metadata.value, original, changes);
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
      const oldName = item.name;
      item.metadata = value;
      item.name = nextName;
      if (!isPlace && oldName !== nextName) {
        for (const transition of draft.transitions) {
          if (transition.metadata?.recursion?.base_case === oldName) transition.metadata.recursion.base_case = nextName;
          if (Array.isArray(transition.metadata?.atomic_with)) {
            transition.metadata.atomic_with = transition.metadata.atomic_with.map(reference =>
              typeof reference === "string" && reference.toLowerCase() === oldName.toLowerCase() ? nextName : reference);
          }
        }
      }
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

function fixtureInspector(panel) {
  const fixture = model.fixture;
  panel.replaceChildren(element("h2", label(121)), element("p", label(122), "draft-note"));
  const verdict = value => value === true ? label(128) : value === false ? label(129) : label(130);
  const checks = Array.isArray(fixture.node_verdicts) && fixture.node_verdicts.length
    ? fixture.node_verdicts.map((value, index) => "vin " + index + " · " + verdict(value)).join(" / ")
    : label(130);
  panel.append(description(label(131), [
    [label(116), fixture.txid], [label(120), bytes(fixture.bytes)],
    [label(126), checks], [label(127), verdict(fixture.chain_gang)],
  ]));
  const node = graphModel().nodes.get(activeNode);
  if (node) {
    const collection = node.kind === "place" ? fixtureGraph.places : fixtureGraph.transitions;
    const item = collection.find(entry => entry.name === node.title);
    panel.append(description(label(29) + " · " + node.title, [
      [node.kind === "place" ? "Place" : "Transition", node.detail],
    ]));
    const declared = declarations(item?.metadata);
    if (declared.length) panel.append(description(label(140), declared));
    if (item?.metadata) {
      const section = element("section", undefined, "details");
      section.append(element("h3", label(134)), element("pre", JSON.stringify(item.metadata, null, 2), "forth"));
      panel.append(section);
    }
  }
  for (const [heading, entries] of [[137, fixture.inputs], [138, fixture.outputs]]) {
    const section = element("section", undefined, "details ports");
    section.append(element("h3", label(heading) + " (" + entries.length + ")"));
    entries.forEach((entry, index) => {
      const place = fixtureGraph.places.find(item => item.metadata?.actual_outpoint === entry.outpoint ||
        item.name === entry.outpoint);
      if (node?.kind === "place" && node.title !== place?.name) return;
      const detail = element("details");
      detail.open = true;
      detail.append(element("summary", (heading === 137 ? "vin " : "vout ") + index + " · " + entry.kind, "mono"));
      const values = element("dl");
      const outpoint = element("dd");
      if (place) {
        outpoint.append(draftButton(entry.outpoint, () => {
          activeNode = "fixture:place:" + place.name;
          renderGraph(true);
          renderCandidates();
          renderInspector();
        }));
      } else outpoint.textContent = entry.outpoint;
      values.append(element("dt", label(34)), outpoint);
      for (const [key, value] of [[35, entry.satoshis === undefined ? null : entry.satoshis + " sat"],
        [132, entry.quantity], [133, entry.owner]]) {
        if (value === undefined || value === null) continue;
        values.append(element("dt", label(key)), element("dd", value, key === 133 ? "mono outpoint" : ""));
      }
      detail.append(values);
      section.append(detail);
    });
    panel.append(section);
  }
  const actions = element("div", undefined, "actions");
  actions.append(download(label(139), "cpn-fixture-bundle.json", model.bundle),
    download(label(135), "cpn-fixture-model.json", fixtureGraph));
  panel.append(actions);
}

function renderInspector() {
  if (view === "draft") { draftInspector($("inspector")); return; }
  if (view === "fixture") { fixtureInspector($("inspector")); return; }
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
  recursionStatements(panel, row);
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
    if (node.proof) {
      panel.append(description(label(149), [
        [label(150), node.proof.backend],
        [label(154), node.proof.statement.public?.join(" · ")],
        [label(151), node.proof.statement_sha256],
        [label(152), node.proof.verification_key_sha256],
        [label(model.packages[selected]?.receipt ? 142 : 141), ""],
      ]));
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
  if (view === "draft" || view === "fixture") {
    const net = view === "fixture" ? fixtureGraph : draft;
    const list = $("candidates");
    list.replaceChildren();
    const items = [
      ...net.places.map(item => ({kind: "place", item})),
      ...net.transitions.map(item => ({kind: "transition", item})),
    ].filter(({item}) => item.name.toLowerCase().includes(query));
    if (!items.length) list.append(element("li", label(106), "empty"));
    for (const {kind, item} of items) {
      const li = element("li"), button = element("button", undefined, "candidate");
      const identity = view + ":" + kind + ":" + item.name;
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
      replayIndex = -1;
      renderCandidates();
      list.querySelector('[aria-pressed="true"]')?.focus();
      renderReplay();
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
  if (view === "draft" || view === "fixture") {
    $("heading").textContent = label(view === "fixture" ? 121 : 104);
    $("rail-title").textContent = label(105);
  }
  $("stats").hidden = view === "draft" || view === "fixture";
  $("filters").hidden = view === "draft" || view === "fixture";
  const contexts = {bip143: "BIP143 ALL", otda: "Chronicle OTDA ALL", both: "BIP143 / OTDA ALL"};
  $("context").textContent = model.fixture_mode ? (view === "fixture" ? label(122) : label(125)) :
    model.editor_start ? label(61) :
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
  const choices = model.fixture_mode ? (fixtureCopied ? [["fixture", 124], ["draft", 60]] : [["fixture", 121]]) :
    model.editor_start ? [["draft", 60]] : [["logical", 8], ["physical", 9], ["draft", 60]];
  segments("views", choices, view, key => { activeNode = null; replayIndex = -1; view = key; render(); });
  draftTools();
  for (const button of document.querySelectorAll("[data-lang]")) button.setAttribute("aria-pressed", button.dataset.lang === lang);
  renderCandidates();
  renderReplay();
  renderGraph();
  renderInspector();
}

for (const button of document.querySelectorAll("[data-lang]")) {
  button.addEventListener("click", () => { lang = button.dataset.lang; render(); });
}
$("search").addEventListener("input", renderCandidates);
render();
