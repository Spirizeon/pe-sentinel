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

function renderFeatures(schema) {
  const panel = $('feature-panel');
  if (!schema.length) {
    panel.hidden = true;
    $('criterion-features-text').textContent = '';
    return;
  }
  panel.hidden = false;
  $('feature-summary').textContent =
    `${schema.length} features extracted from this sample. Dual-use APIs are excluded from high-signal categories.`;
  $('criterion-features-text').textContent = `${schema.length} static features · deterministic schema`;
  const tbody = $('feature-body');
  tbody.replaceChildren();
  schema.forEach((item, index) => {
    const tr = el('tr');
    tr.append(el('td', 'muted', index + 1));
    tr.append(el('td', 'feature-cell', item.name));
    tr.append(el('td', '', item.value));
    tr.append(el('td', 'muted', item.description));
    tbody.append(tr);
  });
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

  const attributions = report.top_attributions || [];
  const evidence = report.evidence || [];
  const schema = report.feature_schema || [];
  const featureCount = report.feature_count || schema.length;

  const badges = $('proof-badges');
  badges.replaceChildren();
  badges.append(el('span', 'badge badge-ok', `${featureCount} features`));
  badges.append(el('span', 'badge badge-ok', `${attributions.length} SHAP values`));
  badges.append(el('span', 'badge badge-ok', `${evidence.length} evidence lines`));
  $('criterion-explain-text').textContent =
    `${attributions.length} SHAP values + ${evidence.length} evidence lines`;

  const tbody = $('attrib-body');
  tbody.replaceChildren();
  for (const item of attributions) {
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
  for (const line of evidence) list.append(el('li', '', line));

  $('raw-evidence').textContent = JSON.stringify(report.raw_evidence || {}, null, 2);
  $('file-meta').textContent =
    `${report.uploaded_filename || report.file} · SHA-256 ${report.sha256} · ` +
    `${report.size_bytes.toLocaleString()} bytes · model: ${report.model} · explainer: ${report.explainer}`;

  renderFeatures(schema);
}

function renderMetrics(data) {
  $('metrics-summary').textContent =
    `${Object.keys(data.models).length} models · ${data.selection_criterion}.`;
  $('criterion-models-text').textContent =
    `${Object.keys(data.models).length} models · 5-fold cross-validation`;

  const best = data.models[data.best_model];
  const summary = $('selected-summary');
  summary.replaceChildren();
  summary.append(el('div', 'summary-title', `Selected model: ${data.best_model}`));
  const stats = [
    ['Accuracy', best.test.accuracy.toFixed(4)],
    ['F1', best.test.f1.toFixed(4)],
    ['False positives', best.test.false_positive_count],
    ['FPR', best.test.false_positive_rate.toFixed(3)],
    ['Inference', `${best.inference.per_sample_ms_single.toFixed(2)} ms`],
  ];
  for (const [label, value] of stats) {
    const card = el('div', 'stat-card');
    card.append(el('span', 'stat-label', label));
    card.append(el('strong', 'stat-value', value));
    summary.append(card);
  }
  $('criterion-eval-text').textContent =
    `Acc ${best.test.accuracy.toFixed(3)} · F1 ${best.test.f1.toFixed(3)} · ` +
    `FP ${best.test.false_positive_count} · ${best.inference.per_sample_ms_single.toFixed(1)} ms`;

  const tbody = $('metrics-body');
  tbody.replaceChildren();
  for (const [name, result] of Object.entries(data.models)) {
    const cm = result.test.confusion_matrix;
    const tr = el('tr');
    if (name === data.best_model) tr.className = 'row-best';
    const values = [
      name === data.best_model ? `${name} ★` : name,
      result.cv.accuracy_mean.toFixed(4),
      result.cv.f1_mean.toFixed(4),
      result.test.accuracy.toFixed(4),
      result.test.f1.toFixed(4),
      result.test.precision.toFixed(4),
      result.test.recall.toFixed(4),
      result.test.roc_auc.toFixed(4),
      cm.tp, cm.fp, cm.fn, cm.tn,
      result.test.false_positive_rate.toFixed(3),
      result.inference.per_sample_ms_single.toFixed(2),
    ];
    values.forEach((value, index) => tr.append(el('td', index === 0 ? 'feature-cell' : '', value)));
    tbody.append(tr);
  }

  $('metrics-panel').hidden = false;
}

async function analyzeFile(file) {
  setBusy(true);
  try {
    const form = new FormData();
    form.append('file', file);
    renderReport(await api('/api/predict', { method: 'POST', body: form }));
  } catch (error) { showError(error.message); }
  finally { setBusy(false); }
}

async function loadDemo() {
  setBusy(true);
  try { renderReport(await api('/api/target-report')); }
  catch (error) { showError(error.message); }
  finally { setBusy(false); }
}

async function loadMetrics() {
  setBusy(true);
  try { renderMetrics(await api('/api/metrics')); }
  catch (error) { showError(error.message); }
  finally { setBusy(false); }
}

async function scrollToPanel(id) {
  if (id === 'metrics-panel' && $('metrics-panel').hidden) await loadMetrics();
  const target = $(id);
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
  $('demo-btn').addEventListener('click', loadDemo);
  $('metrics-btn').addEventListener('click', loadMetrics);
  $('criterion-demo-btn').addEventListener('click', loadDemo);
  $('criterion-metrics-btn').addEventListener('click', loadMetrics);
  document.querySelectorAll('[data-scroll]').forEach((button) => {
    button.addEventListener('click', () => scrollToPanel(button.dataset.scroll));
  });
}

init();
