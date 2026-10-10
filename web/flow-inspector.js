// Node property panel for the flow editor. Mutates the working definition
// object in place and calls handlers.onChange() after every edit.
window.FlowInspector = (() => {
  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('"', '&quot;');
  }

  function nodeAliases(def) {
    return def.graph.nodes.map((n) => n.alias);
  }

  function renderInputs(root, node, info, def, handlers) {
    const wrap = document.createElement('div');
    wrap.innerHTML = `<strong>Inputs</strong>`;
    for (const spec of info.inputs || []) {
      const row = document.createElement('div');
      row.className = 'row';
      row.style.alignItems = 'center';
      row.style.gap = '.4rem';
      row.style.marginTop = '.3rem';
      const label = document.createElement('span');
      label.className = 'small';
      label.style.minWidth = '7.5rem';
      label.textContent = `${spec.name}${spec.required ? ' *' : ''} (${spec.kind})`;
      row.appendChild(label);
      const prop = node.inputs[spec.name];
      const isRef = prop && prop.kind === 'ref';
      const mode = document.createElement('button');
      mode.type = 'button';
      mode.className = 'btn fit';
      mode.textContent = isRef ? 'ref' : 'const';
      mode.title = 'Switch between a constant and a reference to another node output';
      mode.onclick = () => {
        if (isRef) {
          node.inputs[spec.name] = { kind: 'const', value: defaultFor(spec.kind) };
        } else {
          node.inputs[spec.name] = { kind: 'ref', node: '', output: '' };
        }
        handlers.onChange();
      };
      row.appendChild(mode);
      if (isRef) {
        const nodeSelect = document.createElement('select');
        nodeSelect.style.flex = '1';
        for (const alias of nodeAliases(def)) {
          if (alias === node.alias) continue;
          const option = document.createElement('option');
          option.value = alias;
          option.textContent = alias;
          if (prop.node === alias) option.selected = true;
          nodeSelect.appendChild(option);
        }
        nodeSelect.onchange = () => {
          prop.node = nodeSelect.value;
          handlers.onChange();
        };
        row.appendChild(nodeSelect);
        const output = document.createElement('input');
        output.placeholder = 'output';
        output.value = prop.output || '';
        output.style.flex = '1';
        output.onchange = () => {
          prop.output = output.value.trim();
          handlers.onChange();
        };
        row.appendChild(output);
      } else {
        const input = document.createElement('input');
        input.style.flex = '1';
        if (spec.kind === 'boolean') {
          input.type = 'checkbox';
          input.style.width = 'auto';
          input.checked = prop?.value === true;
          input.onchange = () => {
            node.inputs[spec.name] = { kind: 'const', value: input.checked };
            handlers.onChange();
          };
        } else {
          input.value = formatConst(prop?.value);
          input.onchange = () => {
            node.inputs[spec.name] = {
              kind: 'const',
              value: parseConst(input.value, spec.kind),
            };
            handlers.onChange();
          };
        }
        row.appendChild(input);
      }
      wrap.appendChild(row);
      if (spec.doc) {
        const doc = document.createElement('p');
        doc.className = 'small muted';
        doc.style.margin = '0 0 0 7.9rem';
        doc.textContent = spec.doc;
        wrap.appendChild(doc);
      }
    }
    root.appendChild(wrap);
  }

  function defaultFor(kind) {
    if (kind === 'number') return 0;
    if (kind === 'boolean') return false;
    if (kind === 'object') return {};
    if (kind === 'array') return [];
    return '';
  }

  function formatConst(value) {
    if (value === undefined || value === null) return '';
    if (typeof value === 'string') return value;
    return JSON.stringify(value);
  }

  function parseConst(text, kind) {
    if (kind === 'number') {
      const n = Number(text);
      return Number.isFinite(n) ? n : 0;
    }
    if (kind === 'boolean') return text === 'true';
    if (kind === 'object' || kind === 'array') {
      try {
        return JSON.parse(text);
      } catch {
        return kind === 'array' ? [] : {};
      }
    }
    return text;
  }

  function renderEdges(root, node, def, handlers) {
    const outgoing = def.graph.edges
      .map((edge, index) => ({ edge, index }))
      .filter(({ edge }) => edge.source.node === node.alias);
    const wrap = document.createElement('div');
    wrap.style.marginTop = '.6rem';
    wrap.innerHTML = `<strong>Exec edges from this node</strong>`;
    if (!outgoing.length) {
      const none = document.createElement('p');
      none.className = 'small muted';
      none.textContent = 'No outgoing exec edges.';
      wrap.appendChild(none);
    }
    for (const { edge, index } of outgoing) {
      const row = document.createElement('div');
      row.className = 'row';
      row.style.gap = '.4rem';
      row.style.marginTop = '.3rem';
      const text = document.createElement('span');
      text.className = 'small mono';
      text.style.flex = '1';
      text.textContent = `${edge.source.node}.${edge.source.port} → ${edge.target.node}.${edge.target.port}`;
      row.appendChild(text);
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'btn fit';
      remove.textContent = 'Remove';
      remove.onclick = () => handlers.onRemoveEdge(index);
      row.appendChild(remove);
      wrap.appendChild(row);
    }
    const connectRow = document.createElement('div');
    connectRow.className = 'row';
    connectRow.style.gap = '.4rem';
    connectRow.style.marginTop = '.4rem';
    const portSelect = document.createElement('select');
    for (const port of info.exec_out || []) {
      const option = document.createElement('option');
      option.value = port;
      option.textContent = `port ${port}`;
      portSelect.appendChild(option);
    }
    connectRow.appendChild(portSelect);
    const targetSelect = document.createElement('select');
    for (const alias of nodeAliases(def)) {
      if (alias === node.alias) continue;
      const option = document.createElement('option');
      option.value = alias;
      option.textContent = `→ ${alias}.exec`;
      targetSelect.appendChild(option);
    }
    connectRow.appendChild(targetSelect);
    const add = document.createElement('button');
    add.type = 'button';
    add.className = 'btn fit';
    add.textContent = 'Connect';
    add.onclick = () => {
      if (!portSelect.value || !targetSelect.value) return;
      handlers.onAddEdge(portSelect.value, targetSelect.value);
    };
    connectRow.appendChild(add);
    wrap.appendChild(connectRow);
    root.appendChild(wrap);
  }

  function mount(root, node, info, def, handlers) {
    root.innerHTML = '';
    if (!node) return;
    const card = document.createElement('div');
    card.className = 'card';
    card.style.marginTop = '.5rem';
    const head = document.createElement('div');
    head.className = 'row';
    head.style.alignItems = 'center';
    const title = document.createElement('strong');
    title.textContent = `${info.display || node.node_type} (${node.alias})`;
    head.appendChild(title);
    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    head.appendChild(spacer);
    const aliasLabel = document.createElement('span');
    aliasLabel.className = 'small muted';
    aliasLabel.textContent = 'alias';
    head.appendChild(aliasLabel);
    const aliasInput = document.createElement('input');
    aliasInput.value = node.alias;
    aliasInput.style.width = '8rem';
    aliasInput.onchange = () => {
      const next = aliasInput.value.trim();
      if (!next || next === node.alias) return;
      if (def.graph.nodes.some((n) => n.alias === next)) {
        aliasInput.value = node.alias;
        return;
      }
      handlers.onRenameNode(node.alias, next);
    };
    head.appendChild(aliasInput);
    const removeNode = document.createElement('button');
    removeNode.type = 'button';
    removeNode.className = 'btn fit';
    removeNode.textContent = 'Delete node';
    removeNode.onclick = () => handlers.onDeleteNode(node.alias);
    head.appendChild(removeNode);
    card.appendChild(head);
    if (info.doc) {
      const doc = document.createElement('p');
      doc.className = 'small muted';
      doc.textContent = info.doc;
      card.appendChild(doc);
    }
    renderInputs(card, node, info, def, handlers);
    renderEdges(card, node, def, handlers);
    root.appendChild(card);
  }

  return { mount };
})();
