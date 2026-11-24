'use strict';

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function api(path, options) {
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch (_) { throw new Error('Server returned non-JSON response'); }
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function showError(message) {
  const box = $('error-box');
  box.textContent = message;
  box.hidden = false;
}

function clearError() { $('error-box').hidden = true; }

function setBusy(busy) {
  $('loader').hidden = !busy;
  $('analyze-btn').disabled = busy || !$('file-input').files.length;
  $('demo-btn').disabled = busy;
  $('metrics-btn').disabled = busy;
}

function renderReport(report) {
  clearError();
  $('empty-result').hidden = true;
  $('result').hidden = false;

  const malicious = report.prediction === 'malicious';
  const verdict = $('verdict');
  verdict.textContent = report.prediction.toUpperCase();
  verdict.className = `verdict ${malicious ? 'verdict-bad' : 'verdict-good'}`;

  const probability = report.malware_probability;
  $('probability').textContent = `${(probability * 100).toFixed(1)}% malware`;
  $('gauge-fill').style.width = `${Math.max(0, Math.min(100, probability * 100))}%`;
  $('gauge-fill').className = `gauge-fill ${malicious ? 'fill-bad' : 'fill-good'}`;

  const tbody = $('attrib-body');
  tbody.replaceChildren();
  for (const item of report.top_attributions || []) {
    const tr = el('tr');
    const feature = el('td', 'feature-cell', item.feature);
    feature.title = item.description || '';
    tr.append(feature);
    tr.append(el('td', '', item.value));
    const shap = el('td', item.shap_value > 0 ? 'shap-up' : 'shap-down',
      `${item.shap_value > 0 ? '+' : ''}${item.shap_value}`);
    tr.append(shap);
    tr.append(el('td', '', item.direction === 'towards_malware' ? 'malware ▲' : 'benign ▼'));
    tbody.append(tr);
  }

  const list = $('evidence-list');
  list.replaceChildren();
  for (const line of report.evidence || []) list.append(el('li', '', line));

  $('raw-evidence').textContent = JSON.stringify(report.raw_evidence || {}, null, 2);
  $('file-meta').textContent =
    `${report.uploaded_filename || report.file} · SHA-256 ${report.sha256} · ` +
    `${report.size_bytes.toLocaleString()} bytes · model: ${report.model} · explainer: ${report.explainer}`;
}

function renderMetrics(data) {
  $('metrics-summary').textContent = `${data.selection_criterion}. Selected: ${data.best_model}.`;
  const tbody = $('metrics-body');
  tbody.replaceChildren();
  for (const [name, result] of Object.entries(data.models)) {
    const tr = el('tr');
    if (name === data.best_model) tr.className = 'row-best';
    tr.append(el('td', '', name === data.best_model ? `${name} ★` : name));
    tr.append(el('td', '', result.cv.f1_mean.toFixed(4)));
    tr.append(el('td', '', result.test.accuracy.toFixed(4)));
    tr.append(el('td', '', result.test.f1.toFixed(4)));
    tr.append(el('td', '', result.test.false_positive_count));
    tr.append(el('td', '', result.test.false_positive_rate.toFixed(3)));
    tr.append(el('td', '', result.inference.per_sample_ms_single.toFixed(2)));
    tbody.append(tr);
  }
  $('metrics-panel').hidden = false;
  $('metrics-panel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function analyzeFile(file) {
  setBusy(true);
  try {
    const form = new FormData();
    form.append('file', file);
    const report = await api('/api/predict', { method: 'POST', body: form });
    renderReport(report);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
}

function selectFile(file) {
  if (!file) return;
  $('file-input').files = (() => {
    const dt = new DataTransfer();
    dt.items.add(file);
    return dt.files;
  })();
  $('dropzone-title').textContent = file.name;
  $('analyze-btn').disabled = false;
}

async function init() {
  try {
    const health = await api('/api/health');
    const badge = $('model-badge');
    badge.textContent = health.model_ready ? 'model ready' : 'model missing — run training';
    badge.className = health.model_ready ? 'badge badge-ok' : 'badge badge-wait';
  } catch (error) { showError(error.message); }

  $('file-input').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
      $('dropzone-title').textContent = file.name;
      $('analyze-btn').disabled = false;
    }
  });

  const dropzone = $('dropzone');
  dropzone.addEventListener('dragover', (event) => { event.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('dragover');
    selectFile(event.dataTransfer.files[0]);
  });

  $('analyze-btn').addEventListener('click', () => {
    const file = $('file-input').files[0];
    if (file) analyzeFile(file);
  });

  $('demo-btn').addEventListener('click', async () => {
    setBusy(true);
    try { renderReport(await api('/api/target-report')); }
    catch (error) { showError(error.message); }
    finally { setBusy(false); }
  });

  $('metrics-btn').addEventListener('click', async () => {
    setBusy(true);
    try { renderMetrics(await api('/api/metrics')); }
    catch (error) { showError(error.message); }
    finally { setBusy(false); }
  });
}

init();
