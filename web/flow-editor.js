// Flow list, SVG graph editor, run controls, and job watcher.
// Talks to the page-global FlowApi and the FlowInspector panel.
window.HuntFlows = (() => {
  const NODE_W = 158;
  const NODE_H = 58;
  let projectId = null;
  let catalog = [];
  let catalogMap = {};
  let flows = [];
  let flow = null; // stored Flow row
  let def = null; // working FlowDefinition clone
  let selectedAlias = null;
  let armedPort = null; // { node, port } output awaiting a target
  let drag = null;
  let jobTimer = null;
  let saveTimer = null;

  const $id = (id) => document.getElementById(id);

  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('"', '&quot;');
  }

  function status(message, kind = '') {
    const el = $id('flowStatus');
    if (!el) return;
    el.textContent = message || '';
    el.className = `status${kind ? ` ${kind}` : ''}`;
  }

  function info(aliasOrType) {
    return (
      catalogMap[aliasOrType] || {
        type_name: aliasOrType,
        display: aliasOrType,
        doc: '',
        inputs: [],
        outputs: [],
        exec_in: ['exec'],
        exec_out: ['ok'],
      }
    );
  }

  function nodeByAlias(alias) {
    return def?.graph?.nodes?.find((n) => n.alias === alias) || null;
  }

  function ensureLayout() {
    def.graph.nodes.forEach((node, index) => {
      if (!node.display || typeof node.display.x !== 'number') {
        node.display = { x: 24 + (index % 3) * 190, y: 24 + Math.floor(index / 3) * 100 };
      }
    });
  }

  async function loadCatalog() {
    if (catalog.length) return;
    const result = await FlowApi.nodes();
    catalog = result.nodes || [];
    catalogMap = Object.fromEntries(catalog.map((n) => [n.type_name, n]));
  }

  async function loadFlows() {
    if (!projectId) {
      flows = [];
      renderList();
      return;
    }
    const result = await FlowApi.list(projectId);
    flows = result.flows || [];
    renderList();
  }

  function renderList() {
    const list = $id('flowList');
    const empty = $id('flowsEmpty');
    if (!list) return;
    list.innerHTML = '';
    empty?.classList.toggle('hidden', flows.length > 0);
    for (const item of flows) {
      const row = document.createElement('div');
      row.className = 'row';
      row.style.alignItems = 'center';
      row.style.gap = '.4rem';
      row.style.marginBottom = '.3rem';
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'btn fit';
      button.style.flex = '1';
      button.style.textAlign = 'left';
      button.textContent = `${item.enabled ? '●' : '○'} ${item.name} (${item.kind})`;
      button.onclick = () => selectFlow(item.id).catch((e) => status(e.message, 'err'));
      row.appendChild(button);
      list.appendChild(row);
    }
  }

  async function selectFlow(flowId) {
    flow = await FlowApi.get(projectId, flowId);
    def = structuredClone(flow.definition);
    ensureLayout();
    selectedAlias = def.graph.nodes[0]?.alias || null;
    armedPort = null;
    $id('flowEditorEmpty')?.classList.add('hidden');
    $id('flowEditor')?.classList.remove('hidden');
    renderEditor();
    await loadJobs();
  }

  function renderEditor() {
    if (!flow || !def) return;
    $id('flowEditorTitle').textContent = def.name || flow.name;
    $id('flowEditorMeta').textContent =
      `${def.kind} flow · edition ${def.edition} · ${flow.enabled ? 'enabled' : 'disabled'}` +
      (def.description ? ` · ${def.description}` : '');
    const toggle = $id('flowToggleEnabled');
    if (toggle) toggle.textContent = flow.enabled ? 'Disable' : 'Enable';
    renderPalette();
    renderCanvas();
    renderInspector();
    syncJson();
  }

  function renderPalette() {
    const palette = $id('flowPalette');
    if (!palette) return;
    palette.innerHTML = '';
    for (const node of catalog) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'btn fit';
      button.textContent = `+ ${node.display}`;
      button.title = node.doc || node.type_name;
      button.onclick = () => addNode(node.type_name);
      palette.appendChild(button);
    }
  }

  function uniqueAlias(typeName) {
    const base = typeName.split('/').pop().replace(/[^a-z0-9]+/gi, '-');
    let alias = base;
    let n = 2;
    while (nodeByAlias(alias)) alias = `${base}-${n++}`;
    return alias;
  }

  function defaultInputs(nodeInfo) {
    const inputs = {};
    for (const spec of nodeInfo.inputs || []) {
      if (!spec.required) continue;
      const value =
        spec.kind === 'number' ? 0 : spec.kind === 'boolean' ? false : '';
      inputs[spec.name] = { kind: 'const', value };
    }
    return inputs;
  }

  function addNode(typeName) {
    const nodeInfo = info(typeName);
    const alias = uniqueAlias(typeName);
    def.graph.nodes.push({
      type: typeName,
      alias,
      display: {
        x: 24 + (def.graph.nodes.length % 3) * 190,
        y: 24 + Math.floor(def.graph.nodes.length / 3) * 100,
      },
      inputs: defaultInputs(nodeInfo),
    });
    selectedAlias = alias;
    scheduleSave();
  }

  function removeNode(alias) {
    def.graph.nodes = def.graph.nodes.filter((n) => n.alias !== alias);
    def.graph.edges = def.graph.edges.filter(
      (e) => e.source.node !== alias && e.target.node !== alias,
    );
    for (const node of def.graph.nodes) {
      for (const prop of Object.values(node.inputs || {})) {
        if (prop?.kind === 'ref' && prop.node === alias) prop.node = '';
      }
    }
    if (selectedAlias === alias) selectedAlias = def.graph.nodes[0]?.alias || null;
    scheduleSave();
  }

  function renameNode(oldAlias, newAlias) {
    for (const node of def.graph.nodes) {
      if (node.alias === oldAlias) node.alias = newAlias;
      for (const prop of Object.values(node.inputs || {})) {
        if (prop?.kind === 'ref' && prop.node === oldAlias) prop.node = newAlias;
      }
    }
    for (const edge of def.graph.edges) {
      if (edge.source.node === oldAlias) edge.source.node = newAlias;
      if (edge.target.node === oldAlias) edge.target.node = newAlias;
    }
    selectedAlias = newAlias;
    scheduleSave();
  }

  function addEdge(sourceAlias, port, targetAlias) {
    if (sourceAlias === targetAlias) return;
    const exists = def.graph.edges.some(
      (e) =>
        e.source.node === sourceAlias &&
        e.source.port === port &&
        e.target.node === targetAlias &&
        e.target.port === 'exec',
    );
    if (exists) return;
    def.graph.edges.push({
      source: { node: sourceAlias, port },
      target: { node: targetAlias, port: 'exec' },
    });
    scheduleSave();
  }

  function removeEdge(index) {
    def.graph.edges.splice(index, 1);
    scheduleSave();
  }

  function portY(node, index, count) {
    const display = node.display || { x: 0, y: 0 };
    if (count <= 1) return display.y + NODE_H / 2;
    const span = NODE_H - 16;
    return display.y + 8 + (span / Math.max(count - 1, 1)) * index;
  }

  function renderCanvas() {
    const svg = $id('flowCanvas');
    if (!svg || !def) return;
    svg.innerHTML = '';
    const ns = 'http://www.w3.org/2000/svg';
    for (const edge of def.graph.edges) {
      const source = nodeByAlias(edge.source.node);
      const target = nodeByAlias(edge.target.node);
      if (!source || !target) continue;
      const ports = info(source.node_type).exec_out || ['ok'];
      const portIndex = Math.max(ports.indexOf(edge.source.port), 0);
      const x1 = (source.display?.x || 0) + NODE_W;
      const y1 = portY(source, portIndex, ports.length);
      const x2 = target.display?.x || 0;
      const y2 = (target.display?.y || 0) + NODE_H / 2;
      const path = document.createElementNS(ns, 'path');
      const mid = (x1 + x2) / 2;
      path.setAttribute(
        'd',
        `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`,
      );
      path.setAttribute('fill', 'none');
      path.setAttribute(
        'stroke',
        edge.source.port === 'error' ? '#e0af68' : '#7aa2f7',
      );
      path.setAttribute('stroke-width', '1.5');
      svg.appendChild(path);
    }
    for (const node of def.graph.nodes) {
      const display = node.display || { x: 0, y: 0 };
      const group = document.createElementNS(ns, 'g');
      group.setAttribute('transform', `translate(${display.x}, ${display.y})`);
      group.style.cursor = 'grab';
      const rect = document.createElementNS(ns, 'rect');
      rect.setAttribute('width', NODE_W);
      rect.setAttribute('height', NODE_H);
      rect.setAttribute('rx', '6');
      const selected = node.alias === selectedAlias;
      rect.setAttribute(
        'fill',
        selected ? 'rgba(122,162,247,.18)' : 'rgba(255,255,255,.05)',
      );
      rect.setAttribute('stroke', selected ? '#7aa2f7' : '#555');
      rect.setAttribute('stroke-width', selected ? '2' : '1');
      group.appendChild(rect);
      const label = document.createElementNS(ns, 'text');
      label.setAttribute('x', '10');
      label.setAttribute('y', '22');
      label.setAttribute('fill', '#e6e6e6');
      label.setAttribute('font-size', '12');
      label.textContent = `${node.alias}`;
      group.appendChild(label);
      const type = document.createElementNS(ns, 'text');
      type.setAttribute('x', '10');
      type.setAttribute('y', '40');
      type.setAttribute('fill', '#999');
      type.setAttribute('font-size', '10');
      type.textContent = info(node.node_type).display || node.node_type;
      group.appendChild(type);
      const ports = info(node.node_type).exec_out || [];
      ports.forEach((port, index) => {
        const dot = document.createElementNS(ns, 'circle');
        dot.setAttribute('cx', NODE_W);
        dot.setAttribute('cy', String(portY(node, index, ports.length) - display.y));
        dot.setAttribute('r', '5');
        const armed =
          armedPort && armedPort.node === node.alias && armedPort.port === port;
        dot.setAttribute('fill', armed ? '#9ece6a' : port === 'error' ? '#e0af68' : '#7aa2f7');
        dot.style.cursor = 'crosshair';
        dot.onclick = (event) => {
          event.stopPropagation();
          armedPort = armed ? null : { node: node.alias, port };
          renderCanvas();
        };
        group.appendChild(dot);
      });
      const hasExecIn = (info(node.node_type).exec_in || []).length > 0;
      if (hasExecIn) {
        const dot = document.createElementNS(ns, 'circle');
        dot.setAttribute('cx', '0');
        dot.setAttribute('cy', String(NODE_H / 2));
        dot.setAttribute('r', '5');
        dot.setAttribute('fill', armedPort ? '#9ece6a' : '#666');
        dot.style.cursor = 'crosshair';
        dot.onclick = (event) => {
          event.stopPropagation();
          if (armedPort && armedPort.node !== node.alias) {
            addEdge(armedPort.node, armedPort.port, node.alias);
            armedPort = null;
          }
        };
        group.appendChild(dot);
      }
      group.onpointerdown = (event) => {
        if (armedPort) return;
        selectedAlias = node.alias;
        armedPort = null;
        drag = {
          alias: node.alias,
          offsetX: event.clientX - display.x,
          offsetY: event.clientY - display.y,
        };
        group.setPointerCapture?.(event.pointerId);
        renderCanvas();
        renderInspector();
      };
      svg.appendChild(group);
    }
    svg.onpointermove = (event) => {
      if (!drag) return;
      const node = nodeByAlias(drag.alias);
      if (!node) return;
      node.display = {
        x: Math.max(0, Math.round(event.clientX - drag.offsetX)),
        y: Math.max(0, Math.round(event.clientY - drag.offsetY)),
      };
      renderCanvas();
    };
    svg.onpointerup = () => {
      if (!drag) return;
      drag = null;
      scheduleSave();
    };
    svg.onclick = () => {
      if (armedPort) {
        armedPort = null;
        renderCanvas();
      }
    };
  }

  function renderInspector() {
    const root = $id('flowInspector');
    if (!root) return;
    const node = nodeByAlias(selectedAlias);
    if (!node) {
      root.innerHTML = '';
      return;
    }
    FlowInspector.mount(root, node, info(node.node_type), def, {
      onChange: () => scheduleSave(),
      onDeleteNode: (alias) => removeNode(alias),
      onRenameNode: (oldAlias, newAlias) => renameNode(oldAlias, newAlias),
      onRemoveEdge: (index) => removeEdge(index),
      onAddEdge: (port, targetAlias) => addEdge(selectedAlias, port, targetAlias),
    });
  }

  function syncJson() {
    const area = $id('flowJson');
    if (area && def) area.value = JSON.stringify(def, null, 2);
  }

  function applyJson() {
    try {
      const parsed = JSON.parse($id('flowJson').value);
      if (!parsed.graph?.nodes || !parsed.graph?.edges) {
        throw new Error('definition needs graph.nodes and graph.edges');
      }
      def = parsed;
      ensureLayout();
      if (!nodeByAlias(selectedAlias)) {
        selectedAlias = def.graph.nodes[0]?.alias || null;
      }
      scheduleSave();
    } catch (e) {
      status(`Invalid JSON: ${e.message}`, 'err');
    }
  }

  function scheduleSave() {
    renderCanvas();
    renderInspector();
    syncJson();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(save, 400);
  }

  async function save() {
    if (!projectId || !flow || !def) return;
    try {
      flow = await FlowApi.update(projectId, flow.id, def);
      def = structuredClone(flow.definition);
      ensureLayout();
      status('Saved', 'ok');
      renderList();
      renderEditor();
    } catch (e) {
      status(e.message, 'err');
    }
  }

  async function runFlow() {
    if (!projectId || !flow) return;
    try {
      const result = await FlowApi.run(projectId, flow.id);
      status(`Run queued: ${result.job_id}`, 'ok');
      await loadJobs();
    } catch (e) {
      status(e.message, 'err');
    }
  }

  async function toggleEnabled() {
    if (!projectId || !flow) return;
    try {
      await FlowApi.setEnabled(projectId, flow.id, !flow.enabled);
      flow = await FlowApi.get(projectId, flow.id);
      renderList();
      renderEditor();
      status(flow.enabled ? 'Enabled' : 'Disabled', 'ok');
    } catch (e) {
      status(e.message, 'err');
    }
  }

  async function deleteFlow() {
    if (!projectId || !flow) return;
    if (!window.confirm(`Delete flow “${flow.name}”?`)) return;
    try {
      await FlowApi.remove(projectId, flow.id);
      flow = null;
      def = null;
      $id('flowEditor')?.classList.add('hidden');
      $id('flowEditorEmpty')?.classList.remove('hidden');
      renderList();
      status('Deleted', 'ok');
    } catch (e) {
      status(e.message, 'err');
    }
  }

  async function loadJobs() {
    if (!projectId) return;
    clearTimeout(jobTimer);
    const result = await FlowApi.jobs(projectId);
    const jobs = (result.jobs || [])
      .filter((job) => !flow || job.flow_id === flow.id)
      .sort((a, b) => b.started_at_ms - a.started_at_ms)
      .slice(0, 12);
    const list = $id('flowJobList');
    const empty = $id('flowJobsEmpty');
    if (!list) return;
    list.innerHTML = '';
    empty?.classList.toggle('hidden', jobs.length > 0);
    for (const job of jobs) {
      const row = document.createElement('div');
      row.className = 'row';
      row.style.gap = '.4rem';
      row.style.marginTop = '.3rem';
      row.style.alignItems = 'center';
      const label = document.createElement('span');
      label.className = 'small mono';
      label.style.flex = '1';
      const duration = job.duration_ms == null ? '' : ` · ${job.duration_ms} ms`;
      const error = job.error ? ` · ${job.error}` : '';
      label.textContent = `${job.state} · ${job.id.slice(0, 8)}${duration}${error}`;
      row.appendChild(label);
      if (job.state === 'running') {
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'btn fit';
        cancel.textContent = 'Cancel';
        cancel.onclick = async () => {
          try {
            await FlowApi.cancel(projectId, job.id);
            await loadJobs();
          } catch (e) {
            status(e.message, 'err');
          }
        };
        row.appendChild(cancel);
      }
      list.appendChild(row);
    }
    if (jobs.some((job) => job.state === 'running')) {
      jobTimer = setTimeout(() => loadJobs().catch(() => {}), 1000);
    }
  }

  function wire() {
    $id('refreshFlows')?.addEventListener('click', () =>
      loadFlows().catch((e) => status(e.message, 'err')),
    );
    $id('createFlow')?.addEventListener('click', async () => {
      if (!projectId) return status('Select a project first.', 'err');
      const name = $id('newFlowName').value.trim();
      const kind = $id('newFlowKind').value;
      if (!name) return status('Flow name is required.', 'err');
      const definition =
        kind === 'passive'
          ? {
              edition: 1,
              kind: 'passive',
              name,
              graph: {
                nodes: [
                  {
                    type: 'flow/on-intercept-response',
                    alias: 'start',
                    inputs: {},
                  },
                  {
                    type: 'flow/set-color',
                    alias: 'paint',
                    inputs: { color: { kind: 'const', value: 'orange' } },
                  },
                ],
                edges: [
                  {
                    source: { node: 'start', port: 'exec' },
                    target: { node: 'paint', port: 'exec' },
                  },
                ],
              },
            }
          : {
              edition: 1,
              kind: 'active',
              name,
              graph: {
                nodes: [
                  { type: 'flow/manual-start', alias: 'go', inputs: {} },
                  {
                    type: 'flow/template',
                    alias: 'echo',
                    inputs: { template: { kind: 'const', value: 'hello' } },
                  },
                ],
                edges: [
                  {
                    source: { node: 'go', port: 'exec' },
                    target: { node: 'echo', port: 'exec' },
                  },
                ],
              },
            };
      try {
        const created = await FlowApi.create(projectId, definition);
        $id('newFlowName').value = '';
        await loadFlows();
        await selectFlow(created.id);
        status('Created', 'ok');
      } catch (e) {
        status(e.message, 'err');
      }
    });
    $id('flowRun')?.addEventListener('click', () => runFlow());
    $id('flowToggleEnabled')?.addEventListener('click', () => toggleEnabled());
    $id('flowDelete')?.addEventListener('click', () => deleteFlow());
    $id('flowApplyJson')?.addEventListener('click', () => applyJson());
  }

  async function init() {
    wire();
    try {
      await loadCatalog();
      renderPalette();
    } catch (e) {
      status(`Node catalog failed: ${e.message}`, 'err');
    }
  }

  return {
    init,
    setProject(id) {
      projectId = id;
      flow = null;
      def = null;
      clearTimeout(jobTimer);
      $id('flowEditor')?.classList.add('hidden');
      $id('flowEditorEmpty')?.classList.remove('hidden');
      loadFlows().catch((e) => status(e.message, 'err'));
    },
    onShow() {
      loadFlows().catch(() => {});
    },
    onEvent() {
      if (!projectId) return;
      loadJobs().catch(() => {});
      loadFlows().catch(() => {});
    },
  };
})();
