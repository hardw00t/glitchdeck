import {
  mergeEvents,
  chunkBytes,
  percentile,
  numericValue,
  duplicateTotal,
  matchesFilter, faultFired, faultTag, streamPreview, streamOutcome,
} from "./model.mjs";
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const definitions = [
  {
    type: "tcp-rst",
    name: "TCP RST",
    desc: "SEVER THE CONNECTION",
    params: { after_bytes: 64, before_headers: false },
    match: { probability: 100 },
    controls: [
      ["Probability", "probability", "range", 0, 100, 1, "%"],
      [
        "Target",
        "path_prefix",
        "select",
        [
          ["", "All"],
          ["/api/", "/api/*"],
          ["/webhooks/", "/webhook"],
        ],
      ],
    ],
  },
  {
    type: "dup-webhook",
    name: "DUP WEBHOOK",
    desc: "REPLAY THE REQUEST",
    params: { count: 2, delay_ms: 150 },
    match: { method: "POST", path_prefix: "/webhooks/payment" },
    controls: [
      [
        "Copies",
        "count",
        "select",
        [
          [2, "2×"],
          [3, "3×"],
          [5, "5×"],
        ],
      ],
      ["Spacing", "delay_ms", "range", 0, 500, 10, "ms"],
    ],
  },
  {
    type: "rate-limit",
    name: "429 STORM",
    desc: "THROTTLE THE CLIENT",
    params: { status: 429, retry_after_sec: 5, body: "Too Many Requests" },
    match: { probability: 80 },
    controls: [
      ["Rate", "probability", "range", 0, 100, 1, "%"],
      [
        "Retry-After",
        "retry_after_sec",
        "select",
        [
          [1, "1s"],
          [2, "2s"],
          [5, "5s"],
        ],
      ],
    ],
  },
  {
    type: "byte-trickle",
    name: "BYTE TRICKLE",
    desc: "SLOW THE RESPONSE",
    params: { bytes_per_sec: 256, chunk_bytes: 128 },
    match: {},
    controls: [
      ["Speed", "bytes_per_sec", "range", 16, 512, 16, " B/s"],
      ["Chunk", "chunk_duration", "range", 50, 500, 10, "ms"],
    ],
  },
  {
    type: "latency-wave",
    name: "LATENCY WAVE",
    desc: "DELAY UPSTREAM",
    params: { shape: "jitter", base_ms: 0, amp_ms: 250 },
    match: {},
    controls: [
      ["Base", "base_ms", "range", 0, 2000, 50, "ms"],
      ["Jitter", "amp_ms", "range", 0, 500, 10, "ms"],
    ],
  },
  {
    type: "ws-glitch",
    name: "WS GLITCH",
    desc: "DISRUPT THE FRAME",
    params: {
      dir: "s2c",
      action: "close_1006",
      after_frames: 3,
      delay_ms: 1000,
    },
    match: { path_prefix: "/ws/ticker" },
    controls: [
      [
        "Mode",
        "action",
        "select",
        [
          ["close_1006", "1006 Drop"],
          ["corrupt", "Corrupt"],
          ["delay", "Stall"],
        ],
      ],
      ["After", "after_frames", "range", 1, 20, 1, " frames"],
    ],
  },
  {
    type: "sse-glitch", name: "SSE GLITCH", desc: "BREAK THE TOKEN STREAM",
    params: {action:"stall", after_events:8, stall_ms:1500}, match:{path_prefix:"/api/chat/stream"},
    controls: [["Mode","action","select",[["stall","Stall"],["drop","Drop"],["truncate","Truncate"],["corrupt_json","Corrupt JSON"],["eof_early","Early EOF"]]],["After","after_events","range",1,40,1," ev"],["Stall","stall_ms","range",100,5000,100,"ms"]],
  },
  {
    type: "h2-grpc", name: "H2 / gRPC", desc: "DISRUPT H2 & RPC FRAMES",
    params: {action:"rst_stream"}, match:{probability:100},
    controls: [["Mode","action","select",[["rst_stream","RST_STREAM"],["goaway","GOAWAY"],["grpc_14","gRPC 14 UNAVAILABLE"],["grpc_4","gRPC 4 DEADLINE"]]],["Rate","probability","range",0,100,1,"%"],["Target","path_prefix","select",[["","All"],["/grpc.","/grpc.*"],["/api/","/api/*"]]]],
  },
];
let config = { rules: [] },
  events = [],
  logCutoff = 0,
  filter = "all",
  preset = -1,
  stream,
  socket,
  tickerBroken = false,
  recording = false,
  tape = { elapsed_ms: 0, events: 0 },
  demo = false,
  refreshTimer;
const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const moduleType = (type) => type === "h2-glitch" || type === "grpc-glitch" ? "h2-grpc" : type;
const ruleFor = (type) => config.rules.find((r) => moduleType(r.fault.type) === type);
const defaultRule = (d) => ({
  id: d.type,
  enabled: false,
  match: { ...d.match },
  fault: { type: d.type === "h2-grpc" ? "h2-glitch" : d.type, params: { ...d.params } },
  virtual: true,
});
function normalize(rules) {
  return (rules || []).map((r) => ({
    ...r,
    match: r.match || {},
    fault: { ...r.fault, params: r.fault.params || {} },
  }));
}
function ensureRules() {
  for (const d of definitions)
    if (!ruleFor(d.type)) {
      const r = defaultRule(d);
      while (config.rules.some((existing) => existing.id === r.id))
        r.id += "-ui";
      config.rules.push(r);
    }
}
async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok)
    throw new Error((await response.text()) || `HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}
function message(text) {
  $("#notice").textContent = text;
  clearTimeout(message.timer);
  message.timer = setTimeout(() => ($("#notice").textContent = ""), 4000);
}
function post(path, body) {
  return api(path, {
    method: "POST",
    ...(body === undefined
      ? {}
      : {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
  });
}
async function replaceRules(rules) {
  await api("/api/faults", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rules: rules.map(({ virtual, ...r }) => r) }),
  });
}
async function patchRule(rule, patch) {
  try {
    if (rule.virtual) {
      const state = await api("/api/state");
      config.rules = normalize(state.rules);
      ensureRules();
      const current = ruleFor(moduleType(rule.fault.type));
      if (current.virtual) {
        Object.assign(
          current,
          patch.enabled === undefined ? {} : { enabled: patch.enabled },
        );
        Object.assign(current.match, patch.match || {});
        Object.assign(current.fault.params, patch.params || {});
        await replaceRules(config.rules);
      } else
        await api(`/api/faults/${encodeURIComponent(current.id)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(patch),
        });
    } else
      await api(`/api/faults/${encodeURIComponent(rule.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
  } catch (e) {
    message(`Could not update faults: ${e.message}`);
    await loadState();
  }
}
function controls(d, r) {
  return d.controls
    .map(([label, key, kind, a, b, step, suffix]) => {
      let value =
        key === "probability"
          ? numericValue(r.match.probability, 100)
          : key === "path_prefix"
            ? r.match.path_prefix || ""
            : key === "chunk_duration"
              ? Math.max(
                  50,
                  Math.min(
                    500,
                    Math.round(
                      (numericValue(r.fault.params.chunk_bytes, 128) * 1000) /
                        numericValue(r.fault.params.bytes_per_sec, 256),
                    ),
                  ),
                )
              : kind === "range"
                ? numericValue(d.type === "sse-glitch" && key === "after_events" && ["drop","corrupt_json"].includes(r.fault.params.action) ? r.fault.params.every : r.fault.params[key], d.params[key])
                : (d.type === "h2-grpc" && key === "action" && r.fault.type === "grpc-glitch" ? `grpc_${r.fault.params.code === "DEADLINE_EXCEEDED" || r.fault.params.code === 4 ? 4 : 14}` : (r.fault.params[key] ?? d.params[key]));
      const id = `${d.type}-${key}`;
      if (kind === "select") {
        const options = a
          .map(
            ([v, t]) =>
              `<option value="${v}" ${String(v) === String(value) ? "selected" : ""}>${t}</option>`,
          )
          .join("");
        return `<div class="control">
          <label for="${id}">${label}</label>
          <select id="${id}" data-key="${key}">${options}</select>
        </div>`;
      }
      value = Math.max(a, Math.min(b, numericValue(value, a)));
      return `<div class="control">
        <label for="${id}">${label}<output>${value}${suffix}</output></label>
        <input id="${id}" data-key="${key}" type="range" min="${a}" max="${b}"
          step="${step}" value="${value}" data-suffix="${suffix}" ${d.type === "sse-glitch" && key === "stall_ms" && r.fault.params.action !== "stall" ? "disabled" : ""}>
      </div>`;
    })
    .join("");
}
function firingCount(type) {
  return events.filter(
    (e) =>
      faultFired(e) &&
      (type === "h2-grpc" ? ["h2-glitch","grpc-glitch"].includes(e.data.fault) : e.type === "ws_frame" ? type === "ws-glitch" : e.data.fault === type),
  ).length;
}
function updateCounts() {
  for (const module of $$(".module")) {
    const n = firingCount(module.dataset.type),
      fire = module.querySelector(".fire");
    fire.textContent = `FIRED: ${n}`;
    fire.classList.toggle("fired", n > 0);
  }
}
function renderModules() {
  ensureRules();
  $("#modules").innerHTML = definitions
    .map((d, i) => {
      const r = ruleFor(d.type),
        n = firingCount(d.type);
      return `<article class="module ${i === 6 ? "violet" : i === 7 ? "cobalt" : i === 5 ? "cyan" : i > 1 ? "amber" : ""} ${r.enabled ? "armed" : ""}" data-type="${d.type}">
        <div class="module-head">
          <span class="module-code">M0${i + 1}</span>
          <h3>${d.name}</h3>
          <span class="led" aria-hidden="true"></span>
          <button class="switch" role="switch" aria-checked="${r.enabled}" aria-label="${d.name}"></button>
        </div>
        <p class="module-desc">${d.desc}</p>
        <span class="fire ${n ? "fired" : ""}">FIRED: ${n}</span>
        <div class="controls">${controls(d, r)}</div>
      </article>`;
    })
    .join("");
}
$("#modules").addEventListener("click", (e) => {
  const button = e.target.closest(".switch");
  if (!button) return;
  const module = button.closest(".module"),
    r = ruleFor(module.dataset.type);
  r.enabled = !r.enabled;
  button.setAttribute("aria-checked", String(r.enabled));
  module.classList.toggle("armed", r.enabled);
  preset = -1;
  markPreset();
  patchRule(r, { enabled: r.enabled });
});
$("#modules").addEventListener("input", (e) => {
  const input = e.target;
  if (!input.dataset.key) return;
  const output = input.parentElement.querySelector("output");
  if (output) output.textContent = input.value + input.dataset.suffix;
  preset = -1;
  markPreset();
});
$("#modules").addEventListener("change", (e) => {
  const input = e.target,
    key = input.dataset.key;
  if (!key) return;
  const r = ruleFor(input.closest(".module").dataset.type),
    value =
      input.tagName === "SELECT" && ["path_prefix", "action"].includes(key)
        ? input.value
        : Number(input.value);
  let patch;
  const type = input.closest(".module").dataset.type;
  if (key === "action" && (type === "h2-grpc" || type === "sse-glitch")) {
    if (type === "h2-grpc") {
      r.fault.type = value.startsWith("grpc_") ? "grpc-glitch" : "h2-glitch";
      r.fault.params = value.startsWith("grpc_") ? {action:"status", code:value === "grpc_14" ? "UNAVAILABLE" : "DEADLINE_EXCEEDED"} : {action:value};
    } else {
      r.fault.params = value === "stall" ? {action:value, after_events:8, stall_ms:1500} :
        ["drop","corrupt_json"].includes(value) ? {action:value, every:2} : {action:value, after_events:8};
    }
    replaceRules(config.rules).then(renderModules).catch((e) => { message(`Could not update faults: ${e.message}`); loadState(); });
    return;
  }
  if (key === "probability" || key === "path_prefix") {
    r.match[key] = value;
    patch = { match: { [key]: value } };
  } else {
    const params = {};
    if (key === "chunk_duration")
      params.chunk_bytes = chunkBytes(
        numericValue(r.fault.params.bytes_per_sec, 256),
        value,
      );
    else {
      params[type === "sse-glitch" && key === "after_events" && ["drop","corrupt_json"].includes(r.fault.params.action) ? "every" : key] = value;
      if (key === "bytes_per_sec")
        params.chunk_bytes = chunkBytes(
          value,
          Number(
            input.closest(".module").querySelector("[data-key=chunk_duration]")
              .value,
          ),
        );
    }
    Object.assign(r.fault.params, params);
    patch = { params };
  }
  patchRule(r, patch);
});
$("#modules").addEventListener("focusout", () =>
  setTimeout(() => {
    if (!$("#modules").contains(document.activeElement)) renderModules();
  }, 0),
);
function markPreset() {
  $$("[data-preset]").forEach((b) =>
    b.classList.toggle("active", Number(b.dataset.preset) === preset),
  );
}
async function applyPreset(n) {
  try {
    const state = await api("/api/state");
    config.rules = normalize(state.rules);
    ensureRules();
    for (const r of config.rules) r.enabled = false;
    const type = ["dup-webhook", "rate-limit", "ws-glitch", "sse-glitch"][n],
      r = ruleFor(type);
    r.enabled = true;
    r.match = { ...definitions.find((d) => d.type === type).match };
    r.fault.params = n === 0 ? {count:2, delay_ms:120} : n === 1
      ? {status:429, retry_after_sec:1, body:"Too Many Requests"}
      : n === 2 ? {dir:"s2c", action:"close_1006", after_frames:3, delay_ms:1000}
      : {action:"truncate", after_events:8};
    await replaceRules(config.rules);
    preset = n;
    renderModules();
    markPreset();
    selectDemoTab(n === 3 ? 1 : 0);
  } catch (e) {
    message(`Could not apply preset: ${e.message}`);
    await loadState();
  }
}
$$("[data-preset]").forEach((b) =>
  b.addEventListener("click", () => applyPreset(Number(b.dataset.preset))),
);
$("#bypass").onclick = async () => {
  try {
    const state = await api("/api/state");
    config.rules = normalize(state.rules);
    config.rules.forEach((r) => (r.enabled = false));
    await replaceRules(config.rules);
    preset = -1;
    markPreset();
    renderModules();
  } catch (e) {
    message(`Could not bypass faults: ${e.message}`);
    await loadState();
  }
};
function setTape(value) {
  tape = value;
  recording = !!value.recording;
  $("#rec-button").classList.toggle("recording", recording);
  $("#tape-counter").classList.toggle("recording", recording);
  $("#rec-button").disabled = recording;
  $("#stop-button").disabled = !recording;
  const exportButton = $("#export-button");
  const exportable = Boolean(value.events || value.incomplete);
  exportButton.classList.toggle("disabled", !exportable);
  exportButton.setAttribute("aria-disabled", String(!exportable));
  const sec = Math.floor((value.elapsed_ms || 0) / 1000);
  $("#tape-counter").textContent =
    `${String(Math.floor(sec / 60)).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")} · ${value.events || 0} EVENTS`;
  $("#tape-warning").textContent = value.incomplete
    ? `INCOMPLETE RECORDING: ${value.incomplete_reason || "Some traffic cannot be replayed."}`
    : "";
}
async function tapeAction(action) {
  try {
    setTape(await post(`/api/tape/${action}`));
  } catch (e) {
    message(`Tape: ${e.message}`);
  }
}
$("#rec-button").onclick = () => tapeAction("record");
$("#stop-button").onclick = () => tapeAction("stop");
$("#copy-cli").onclick = async () => {
  try {
    await navigator.clipboard.writeText("glitchdeck test tape.yaml");
    $("#copy-cli").textContent = "COPIED ✓";
    setTimeout(() => ($("#copy-cli").textContent = "COPY CLI ↗"), 1800);
  } catch {
    message("Clipboard unavailable");
  }
};
$("#export-button").onclick = () => {
  if (tape.events || tape.incomplete) message("Tape exported");
};
function selectTab(index, focus = false) {
  const tabs = [$("#tab-rack"), $("#tab-demo")];
  tabs.forEach((tab, i) => {
    tab.setAttribute("aria-selected", String(i === index));
    tab.tabIndex = i === index ? 0 : -1;
    document.getElementById(
      tab.getAttribute("aria-controls"),
    ).dataset.inactive = String(i !== index);
  });
  if (focus) tabs[index].focus();
}
$$(".tabs [role=tab]").forEach((tab, i) => {
  tab.onclick = () => selectTab(i);
  tab.onkeydown = (e) => {
    if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
      e.preventDefault();
      selectTab(e.key === "Home" ? 0 : e.key === "End" ? 1 : 1 - i, true);
    }
  };
});
selectTab(0);
let lastDemoAlert = "", retryAlert = "", llmAlert = "", llmRun = "", llmPending, llmTimer, llmCutAfter;
function showAlert(text) {
  if (text === lastDemoAlert) return;
  lastDemoAlert = text;
  const el = $("#double-charge-banner");
  el.hidden = !text;
  el.textContent = text;
  $("#alert-count").hidden = !text;
}
async function refreshDemo() {
  if (!demo) return;
  try {
    const s = await api("/api/demo/state");
    const charges = Array.isArray(s.charges) ? s.charges : [];
    $("#ledger-total").textContent =
      `${money(s.total_charged_cents || 0)} TOTAL`;
    const list = $("#ledger");
    list.replaceChildren();
    if (!charges.length) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = "No charges yet";
      list.append(li);
    }
    for (const c of charges.slice(-4).reverse()) {
      const li = document.createElement("li");
      li.className = c.duplicate ? "duplicate" : "";
      li.textContent = `${c.order_id} · ${money(c.amount_cents)} · ${c.duplicate ? "DUP" : "PAID"}`;
      list.append(li);
    }
    const duplicate = duplicateTotal(charges);
    showAlert(
      duplicate
        ? `DOUBLE CHARGE DETECTED: ${money(duplicate.cents)} — order ${duplicate.order}`
        : llmAlert || retryAlert || (tickerBroken ? "WS SILENT DROP: ticker stalled" : ""),
    );
  } catch (e) {
    message(`Demo: ${e.message}`);
  }
}
function money(cents) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format((Number(cents) || 0) / 100);
}
function selectDemoTab(index, focus = false) {
  const tabs = [$("#demo-tab-commerce"), $("#demo-tab-llm")];
  tabs.forEach((tab, i) => {
    tab.setAttribute("aria-selected", String(i === index));
    tab.tabIndex = i === index ? 0 : -1;
    document.getElementById(tab.getAttribute("aria-controls")).hidden = i !== index;
  });
  $("#run-checkout").hidden = index !== 0;
  $("#run-llm").hidden = index !== 1;
  if (focus) tabs[index].focus();
}
[$("#demo-tab-commerce"), $("#demo-tab-llm")].forEach((tab, i) => {
  tab.onclick = () => selectDemoTab(i);
  tab.onkeydown = (e) => {
    if (["ArrowLeft","ArrowRight","Home","End"].includes(e.key)) {
      e.preventDefault();
      selectDemoTab(e.key === "Home" ? 0 : e.key === "End" ? 1 : 1-i, true);
    }
  };
});
function llmStatus(state) {
  $("#llm-status").dataset.state = state;
  $("#llm-status").textContent = state.toUpperCase();
}
function llmFault(text, state) {
  llmAlert = text;
  llmStatus(state);
  showAlert(text);
  const tag = document.createElement("strong");
  tag.className = "llm-fault";
  tag.textContent = ` ${text}`;
  $("#llm-output").append(tag);
}
function watchLLM() {
  clearTimeout(llmTimer);
  llmTimer = setTimeout(() => llmFault("STREAM STALLED: no SSE tokens for 2.5s", "stalled"), 2500);
}
$("#run-llm").onclick = async () => {
  if (llmPending) return;
  llmRun = ""; llmPending = []; llmAlert = ""; llmCutAfter = undefined;
  $("#llm-output").textContent = "";
  $("#llm-count").textContent = "0 TOKENS";
  llmStatus("streaming"); showAlert(""); watchLLM();
  try {
    const result = await post("/api/demo/stream", {flavor:"openai", tokens:24, token_ms:40, wait:false, wedge_after_ms:3000});
    const pending = llmPending;
    llmRun = result.run_id; llmPending = undefined;
    for (const [accept, data] of pending) accept(data);
  } catch (e) {
    llmPending = undefined; clearTimeout(llmTimer);
    llmFault(`STREAM ERROR: ${e.message}`, "truncated");
  }
};
$("#run-grpc").onclick = async () => {
  try {
    const result = await post("/api/demo/grpc");
    message(result.h2_error ? `gRPC H2: ${result.h2_error}` : `gRPC ${result.grpc_status ?? "unavailable"} ${result.grpc_message || ""} · HTTP ${result.http_status}`);
  } catch (e) { message(`gRPC call failed: ${e.message}`); }
};
function acceptDemoStream(d) {
  if (llmPending) {
    if (llmPending.length < 1024) llmPending.push([acceptDemoStream, d]);
    return;
  }
  if (!llmRun || d.run_id !== llmRun) return;
  if (d.phase !== "finished") return;
  clearTimeout(llmTimer);
  $("#llm-output").textContent = d.text || "";
  $("#llm-count").textContent = `${d.tokens || 0} TOKENS`;
  const result = streamOutcome(d, llmCutAfter);
  llmAlert = "";
  llmStatus(result.state);
  if (result.alert) llmFault(result.alert, result.state); else showAlert("");
}
function acceptStreamEvent(d) {
  if (llmPending) {
    if (llmPending.length < 1024) llmPending.push([acceptStreamEvent, d]);
    return;
  }
  if (!llmRun || d.run_id !== llmRun || d.kind !== "event") return;
  if (d.action === "truncate") llmCutAfter = Math.max(0, d.event_index - 1);
  watchLLM();
  const preview = streamPreview(d);
  if (preview.text) {
    $("#llm-output").append(document.createTextNode(preview.text));
    $("#llm-count").textContent = `${Number.parseInt($("#llm-count").textContent, 10) + 1} TOKENS`;
  }
  if (preview.done) $("#llm-status").textContent = "FINISHING";
}
$("#run-checkout").onclick = async () => {
  try {
    const result = await post("/api/demo/trigger");
    retryAlert =
      result.status === 429
        ? `429 RETRY STORM: ${result.retries || 0} retries — checkout stalled`
        : result.error
          ? `CHECKOUT ERROR: ${result.error}`
          : "";
    await refreshDemo();
    setTimeout(refreshDemo, 500);
  } catch (e) {
    message(`Checkout: ${e.message}`);
  }
};
function reportTicker(broken) {
  tickerBroken = broken;
  post("/api/demo/ticker-state", { broken }).catch((e) =>
    message(`Ticker state: ${e.message}`),
  );
  refreshDemo();
}
function setTickerStatus(state) {
  const status = $("#ticker-status");
  status.dataset.state = state;
  status.textContent = state.toUpperCase();
}
$("#connect-ticker").onclick = () => {
  if (socket && socket.readyState < 2) return;
  setTickerStatus("connecting");
  const url = new URL("/api/demo/ticker", location.href);
  url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(url);
  let stallTimer;
  const watch = () => {
    clearTimeout(stallTimer);
    stallTimer = setTimeout(() => {
      setTickerStatus("stalled");
      $("#ticker-meta").textContent = "No ticker frames received";
      reportTicker(true);
    }, 2500);
  };
  socket.onopen = () => {
    setTickerStatus("connected");
    $("#ticker-meta").textContent = "Awaiting tick";
    reportTicker(false);
    watch();
  };
  socket.onmessage = (e) => {
    try {
      const tick = JSON.parse(e.data);
      if (tickerBroken) {
        setTickerStatus("connected");
        reportTicker(false);
      }
      watch();
      $("#ticker-value").textContent =
        typeof tick.price === "number"
          ? money(Math.round(tick.price * 100))
          : "TICK";
      $("#ticker-meta").textContent =
        `seq #${tick.seq} · ${new Date().toLocaleTimeString()}`;
    } catch {
      clearTimeout(stallTimer);
      setTickerStatus("stalled");
      $("#ticker-meta").textContent = "Invalid ticker frame";
      reportTicker(true);
      socket.close();
    }
  };
  socket.onerror = () => {
    reportTicker(true);
  };
  socket.onclose = (e) => {
    clearTimeout(stallTimer);
    setTickerStatus("stalled");
    $("#ticker-meta").textContent = `Connection closed · code ${e.code}`;
    reportTicker(true);
  };
};
function renderLog() {
  const log = $("#wire-log"),
    visible = events
      .filter((e) => e.id > logCutoff && matchesFilter(e, filter))
      .slice(-200)
      .reverse(),
    wanted = new Set(visible.map((e) => String(e.id)));
  $("#event-count").textContent = `${visible.length} EVENTS`;
  for (const row of log.querySelectorAll("details"))
    if (!wanted.has(row.dataset.id)) row.remove();
  const empty = log.querySelector(".empty");
  if (!visible.length) {
    if (!empty) {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = "AWAITING TRAFFIC";
      log.append(p);
    }
    return;
  }
  if (empty) empty.remove();
  const existing = new Set(
    [...log.querySelectorAll("details")].map((row) => row.dataset.id),
  );
  for (const e of visible) {
    if (existing.has(String(e.id))) continue;
    const d = e.data || {},
      row = document.createElement("details");
    row.dataset.id = e.id;
    const tlsFailure = e.type === "tls_handshake_failed";
    const protocol = e.type === "sse_event" ? "sse" : ["grpc_call","h2_frame"].includes(e.type) || ["grpc","h2"].includes(d.protocol) ? "grpc" : e.type === "ws_frame" ? "ws" : "http";
    row.className = "wire-row " + protocol + (faultFired(e) ? " fault" : "");
    const summary = document.createElement("summary");
    const fields = [
      d.ts_ms
        ? new Date(d.ts_ms).toLocaleTimeString("en-GB", { hour12: false }) +
          "." +
          String(new Date(d.ts_ms).getMilliseconds()).padStart(3, "0")
        : "—",
      tlsFailure ? "TLS" : protocol === "sse" ? "SSE" : protocol === "grpc" ? (e.type === "h2_frame" || d.protocol === "h2" ? "H2" : "gRPC") : protocol === "ws" ? "WS" : "HTTP",
      tlsFailure ? `${d.sni || d.host} · ${d.error}` :
        protocol === "sse" ? `${d.event || d.kind || "event"} #${d.event_index || 0} · ${d.preview || ""}` :
        protocol === "grpc" ? `${d.service || ""}/${d.method || ""} ${d.action || ""}` :
        protocol === "ws" ? `${d.dir || ""} · ${d.preview || "frame"}` : `${d.method || ""} ${d.path || ""}`,
      d.grpc_status != null ? `g${d.grpc_status}` : d.h2_error ? "RST" : d.status || d.opcode || "—",
      d.latency_ms != null ? `${d.latency_ms}ms` : d.fault || "—",
    ];
    for (const text of fields) {
      const span = document.createElement("span");
      span.textContent = text;
      summary.append(span);
    }
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(d, null, 2);
    row.append(summary, pre);
    const before = [...log.querySelectorAll("details")].find(
      (item) => Number(item.dataset.id) < e.id,
    );
    log.insertBefore(row, before || null);
  }
}
$$("[data-filter]").forEach(
  (b) =>
    (b.onclick = () => {
      filter = b.dataset.filter;
      $$("[data-filter]").forEach((x) =>
        x.setAttribute("aria-pressed", String(x === b)),
      );
      renderLog();
    }),
);
$("#clear-log").onclick = () => {
  logCutoff = events.length ? events[events.length - 1].id : logCutoff;
  renderLog();
};
function mergeHistory(history) {
  events = mergeEvents(events, history);
  const cutoff = Date.now() - 30000;
  events = events.filter(
    (e, i) => i >= events.length - 200 || e.data?.ts_ms >= cutoff,
  );
  renderLog();
  updateCounts();
}
function accept(event) {
  if (event.type === "fault_state") {
    config.rules = normalize(event.data.rules);
    ensureRules();
    if (!$("#modules").contains(document.activeElement)) renderModules();
    return;
  }
  if (event.type === "demo_stream") { acceptDemoStream(event.data); return; }
  if (event.type === "sse_event") acceptStreamEvent(event.data);
  if (!["http_req", "ws_frame", "sse_event", "grpc_call", "h2_frame", "tls_handshake_failed"].includes(event.type)) return;
  mergeHistory([event]);
  if (demo) {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(refreshDemo, 200);
  }
}
function connectEvents() {
  if (stream) stream.close();
  stream = new EventSource("/api/events");
  stream.onopen = () => {
    $("#disconnect").hidden = true;
    $("#connection").textContent = "LIVE";
    loadState();
    api("/api/history?limit=200")
      .then(mergeHistory)
      .catch((e) => message(`History: ${e.message}`));
  };
  stream.onerror = () => {
    $("#disconnect").hidden = false;
    $("#connection").textContent = "OFFLINE";
  };
  for (const type of ["http_req", "ws_frame", "sse_event", "grpc_call", "h2_frame", "tls_handshake_failed", "demo_stream", "fault_state"])
    stream.addEventListener(type, (e) => {
      try {
        accept({ id: Number(e.lastEventId), type, data: JSON.parse(e.data) });
      } catch {
        message("Invalid telemetry event");
      }
    });
}
$("#reconnect").onclick = connectEvents;
async function loadState() {
  try {
    const s = await api("/api/state");
    config.rules = normalize(s.rules);
    ensureRules();
    demo = !!s.demo_mode;
    $("#demo-pane").hidden = !demo;
    $("#demo-badge").hidden = !demo;
    $("#tls-badge").hidden = !(s.tls_mitm || s.tls_enabled || s.capabilities?.tls_mitm);
    $("#route").textContent = [s.listen, s.target].filter(Boolean).join(" → ");
    if (!$("#modules").contains(document.activeElement)) renderModules();
    if (demo) refreshDemo();
  } catch (e) {
    message(`State: ${e.message}`);
  }
}
const canvas = $("#scope"),
  ctx = canvas.getContext("2d");
const windowMS = 30000;
let animation = 0;

function draw(updateReadouts = false) {
  if (document.hidden) return;
  const w = canvas.clientWidth,
    h = canvas.clientHeight,
    ratio = Math.min(devicePixelRatio || 1, 2);
  if (!w || !h) return;
  const width = Math.round(w * ratio),
    height = Math.round(h * ratio);
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const track = innerWidth <= 800 ? 32 : 44,
    bottom = h - track,
    now = Date.now();
  const recent = events.filter(
    (e) => e.data?.ts_ms >= now - windowMS && e.data.ts_ms <= now,
  );
  const http = recent
    .filter((e) => e.type === "http_req" && Number.isFinite(e.data.latency_ms))
    .sort((a, b) => a.data.ts_ms - b.data.ts_ms);
  const ws = recent.filter((e) => e.type === "ws_frame");
  const sse = recent.filter((e) => e.type === "sse_event" && e.data.kind === "event");
  const maxMS =
    Math.ceil(
      http.reduce((max, e) => Math.max(max, e.data.latency_ms), 1000) / 1000,
    ) * 1000;
  const x = (t) => 4 + ((w - 44) * (t - now + windowMS)) / windowMS;
  const y = (ms) => bottom - 8 - (ms / maxMS) * (bottom - 24);
  function line(x1, y1, x2, y2) {
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();
  }
  ctx.lineWidth = 1;
  ctx.strokeStyle = "rgba(56,245,156,.10)";
  for (let i = 0; i <= 10; i++) line((w * i) / 10, 0, (w * i) / 10, h);
  for (let i = 0; i <= 8; i++) line(0, (bottom * i) / 8, w, (bottom * i) / 8);
  ctx.strokeStyle = "rgba(56,245,156,.22)";
  line(0, bottom, w, bottom);
  for (let i = 1; i < 40; i++)
    line((w * i) / 40, bottom / 2 - 2, (w * i) / 40, bottom / 2 + 2);
  for (let i = 1; i < 32; i++)
    line(w / 2 - 2, (bottom * i) / 32, w / 2 + 2, (bottom * i) / 32);
  ctx.font = "10px monospace";
  ctx.fillStyle = "#91b3a1";
  ctx.textBaseline = "bottom";
  ctx.fillText("0ms", w - 35, y(0) - 5);
  ctx.textBaseline = "alphabetic";
  for (const ms of [maxMS / 4, maxMS / 2, maxMS])
    ctx.fillText(ms >= 1000 ? `${ms / 1000}s` : `${ms}ms`, w - 35, y(ms));
  ctx.fillText("WS / SSE STREAM", 8, bottom + 13);
  ctx.strokeStyle = ctx.fillStyle = "#38f59c";
  ctx.lineWidth = 1.75;
  if (!reduced.matches) {
    ctx.shadowBlur = 6;
    ctx.shadowColor = "rgba(56,245,156,.45)";
  }
  ctx.beginPath();
  if (!http.length) {
    ctx.moveTo(0, y(0));
    ctx.lineTo(w, y(0));
  } else
    http.forEach(({ data }, i) =>
      i
        ? ctx.lineTo(x(data.ts_ms), y(data.latency_ms))
        : ctx.moveTo(x(data.ts_ms), y(data.latency_ms)),
    );
  ctx.stroke();
  for (const { data } of http) {
    ctx.beginPath();
    ctx.arc(x(data.ts_ms), y(data.latency_ms), 3, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.shadowBlur = 0;
  if (!recent.length) {
    ctx.fillStyle = "#91b3a1";
    ctx.textAlign = "center";
    ctx.fillText("PROXY LISTENING · AWAITING TRAFFIC", w / 2, bottom / 2 - 7);
    ctx.textAlign = "start";
  }
  for (const { data } of ws) {
    const px = x(data.ts_ms),
      mid = bottom + track / 2 + 2;
    ctx.strokeStyle = data.fault ? "#ff5968" : "#4cc9f0";
    line(px, mid, px, mid + (data.dir === "s2c" ? -9 : 9));
  }
  for (const e of sse) {
    const {data} = e;
    const px = x(data.ts_ms), mid = bottom + track / 2 + 2;
    ctx.fillStyle = faultFired(e) ? "#ff5968" : "#c084fc";
    ctx.beginPath(); ctx.moveTo(px, mid-3); ctx.lineTo(px+3, mid); ctx.lineTo(px, mid+3); ctx.lineTo(px-3, mid); ctx.closePath(); ctx.fill();
  }
  let previousTag = "",
    previousX = -100;
  for (const e of recent) {
    if (!faultFired(e)) continue;
    const {data} = e;
    const px = x(data.ts_ms),
      close = data.fault === "close_1006",
      tag = close ? "× 1006" : faultTag(data);
    const isSSE = data.fault === "sse-glitch", isH2 = ["h2-glitch","grpc-glitch"].includes(data.fault);
    const color = isSSE ? "#c084fc" : isH2 ? "#7aa2ff" : close ? "#ff5968" : ["429", "TRK", "LAT"].includes(tag) ? "#f5b731" : "#ff5a1f";
    const py = close ? bottom + track - 3 : innerWidth <= 800 ? 29 : 14;
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    if (isSSE || isH2) ctx.setLineDash(isSSE ? [3,3] : [4,2]);
    line(px, close || isSSE ? bottom : 0, px, close || isSSE ? h : bottom);
    ctx.setLineDash([]);
    if (previousTag === tag && px - previousX < 25) continue;
    previousTag = tag;
    previousX = px;
    const labelWidth = ctx.measureText(tag).width + 6,
      left = Math.max(1, px - labelWidth - 3);
    ctx.fillStyle = "#0d0f11";
    ctx.fillRect(left, py - 10, labelWidth, 13);
    ctx.fillStyle = color;
    ctx.fillText(tag, left + 3, py);
  }
  if (updateReadouts) {
    const values = http.map((e) => e.data.latency_ms),
      p50 = percentile(values, 0.5),
      p95 = percentile(values, 0.95);
    const faults = recent.filter(faultFired).length;
    $("#p50").innerHTML = `${p50 ?? "—"} <small>ms</small>`;
    $("#p95").innerHTML = `${p95 ?? "—"} <small>ms</small>`;
    $("#req-rate").textContent = (http.length / 30).toFixed(1);
    $("#ws-rate").textContent = ((ws.length + sse.length) / 30).toFixed(1);
    $("#fault-count").textContent = faults;
    canvas.setAttribute(
      "aria-label",
      recent.length
        ? `Live oscilloscope: P95 ${p95 === null ? "unavailable" : p95 + " milliseconds"}, ${faults} faults fired, ${sse.length} SSE events, ${recent.filter(e => e.type === "grpc_call").length} gRPC calls, WebSocket ${$("#ticker-status").textContent.toLowerCase()}`
        : "Live oscilloscope awaiting traffic",
    );
  }
  if (recent.length && !reduced.matches && !animation)
    animation = requestAnimationFrame(() => {
      animation = 0;
      draw();
    });
}
document.addEventListener("keydown", (e) => {
  if (
    e.altKey ||
    e.ctrlKey ||
    e.metaKey ||
    e.repeat ||
    /INPUT|SELECT|TEXTAREA/.test(e.target.tagName) ||
    e.target.isContentEditable
  )
    return;
  if (e.key.toLowerCase() === "r") tapeAction(recording ? "stop" : "record");
  else if (["1", "2", "3", "4"].includes(e.key)) applyPreset(Number(e.key) - 1);
  else if (e.key === "0") $("#bypass").click();
});
connectEvents();
api("/api/tape/status")
  .then(setTape)
  .catch((e) => message(`Tape: ${e.message}`));
setInterval(() => {
  if (!document.hidden) {
    draw(true);
    if (recording)
      api("/api/tape/status")
        .then(setTape)
        .catch(() => {});
  }
}, 500);
window.addEventListener("resize", () => draw(true));
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) draw(true);
});
draw(true);
