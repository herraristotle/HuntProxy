// REST client for HuntProxy flows. Relies on the page-global api() helper.
window.FlowApi = {
  nodes: () => api('/api/v1/flow-nodes'),
  list: (pid) => api(`/api/v1/projects/${pid}/flows`),
  create: (pid, definition) =>
    api(`/api/v1/projects/${pid}/flows`, {
      method: 'POST',
      body: JSON.stringify({ definition }),
    }),
  get: (pid, fid) => api(`/api/v1/projects/${pid}/flows/${fid}`),
  update: (pid, fid, definition, enabled) =>
    api(`/api/v1/projects/${pid}/flows/${fid}`, {
      method: 'PUT',
      body: JSON.stringify(
        enabled === undefined ? { definition } : { definition, enabled },
      ),
    }),
  remove: (pid, fid) =>
    api(`/api/v1/projects/${pid}/flows/${fid}`, { method: 'DELETE' }),
  setEnabled: (pid, fid, enabled) =>
    api(`/api/v1/projects/${pid}/flows/${fid}/${enabled ? 'enable' : 'disable'}`, {
      method: 'POST',
    }),
  run: (pid, fid, input) =>
    api(`/api/v1/projects/${pid}/flows/${fid}/run`, {
      method: 'POST',
      body: JSON.stringify({ input: input === undefined ? null : input }),
    }),
  jobs: (pid) => api(`/api/v1/projects/${pid}/flow-jobs`),
  job: (pid, jid) => api(`/api/v1/projects/${pid}/flow-jobs/${jid}`),
  cancel: (pid, jid) =>
    api(`/api/v1/projects/${pid}/flow-jobs/${jid}/cancel`, { method: 'POST' }),
};
