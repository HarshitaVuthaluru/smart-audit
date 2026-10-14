import React, { useState } from "react";

const asObject = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};
const asArray = (value) => Array.isArray(value) ? value : [];
const number = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
const formatNumber = (value) => number(value).toLocaleString();
const formatDecimal = (value) => number(value).toFixed(2);
const formatTime = (value) => {
  const seconds = number(value);
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(2)} sec`;
  return `${Math.floor(seconds / 60)} min ${(seconds % 60).toFixed(1)} sec`;
};

function UsageTable({ entries, label }) {
  const rows = asArray(Object.entries(asObject(entries)));
  if (!rows.length) return <p className="text-sm text-gray-500">No {label.toLowerCase()} usage was recorded.</p>;
  return <div className="overflow-x-auto"><table className="min-w-full table-auto text-sm"><thead><tr className="bg-gray-100"><th className="px-4 py-2 text-left">{label}</th><th className="px-4 py-2 text-right">Prompt</th><th className="px-4 py-2 text-right">Completion</th><th className="px-4 py-2 text-right">Total</th><th className="px-4 py-2 text-right">Calls</th></tr></thead><tbody>{Array.isArray(rows) && rows.map(([name, usage]) => {
    const item = asObject(usage);
    return <tr key={name} className="border-b"><td className="px-4 py-2 font-medium">{name}</td><td className="px-4 py-2 text-right">{formatNumber(item.prompt_tokens)}</td><td className="px-4 py-2 text-right">{formatNumber(item.completion_tokens)}</td><td className="px-4 py-2 text-right">{formatNumber(item.total_tokens)}</td><td className="px-4 py-2 text-right">{formatNumber(item.call_count)}</td></tr>;
  })}</tbody></table></div>;
}

function PerformanceMetricsPanel({ metrics }) {
  const [activeTab, setActiveTab] = useState("token");
  const data = asObject(metrics);
  const tokenUsage = asObject(data.token_usage);
  const totals = asObject(tokenUsage.total);
  const timeMetrics = asObject(data.time_metrics);
  const stageTimes = asObject(timeMetrics.stage_times);
  const codeMetrics = asObject(data.code_metrics);
  const derived = asObject(data.derived_metrics);
  const runInfo = asObject(data.run_info);
  const config = asObject(runInfo.config);
  const totalSeconds = number(timeMetrics.total_seconds);

  if (!Object.keys(data).length) return <section className="bg-white shadow-md rounded-lg p-4"><h2 className="text-xl font-semibold">Performance Metrics</h2><p className="mt-2 text-gray-600">No performance data is available for this analysis.</p></section>;

  const tokenContent = <div><h3 className="text-lg font-semibold text-gray-700 mb-2">Token Usage Summary</h3><div className="mb-4 text-gray-600"><p><span className="font-medium">Total Tokens:</span> {formatNumber(totals.total_tokens)}</p><p><span className="font-medium">Prompt Tokens:</span> {formatNumber(totals.prompt_tokens)}</p><p><span className="font-medium">Completion Tokens:</span> {formatNumber(totals.completion_tokens)}</p><p><span className="font-medium">Total API Calls:</span> {formatNumber(totals.call_count)}</p></div><h3 className="text-lg font-semibold text-gray-700 mb-2">Token Usage by Agent</h3><UsageTable entries={tokenUsage.by_agent} label="Agent" /><h3 className="text-lg font-semibold text-gray-700 mt-4 mb-2">Token Usage by Model</h3><UsageTable entries={tokenUsage.by_model} label="Model" /></div>;
  const stageRows = asArray(Object.entries(stageTimes)).sort((a, b) => number(b[1]) - number(a[1]));
  const analyzedFiles = asArray(codeMetrics.files);
  const timeContent = <div><h3 className="text-lg font-semibold text-gray-700 mb-2">Time Metrics</h3><p className="text-gray-600 mb-4"><span className="font-medium">Total Analysis Time:</span> {formatTime(totalSeconds)}</p><h3 className="text-lg font-semibold text-gray-700 mb-2">Time by Stage</h3>{stageRows.length ? <div className="overflow-x-auto"><table className="min-w-full table-auto text-sm"><thead><tr className="bg-gray-100"><th className="px-4 py-2 text-left">Stage</th><th className="px-4 py-2 text-right">Time</th><th className="px-4 py-2 text-right">% of Total</th></tr></thead><tbody>{Array.isArray(stageRows) && stageRows.map(([stage, value]) => <tr key={stage} className="border-b"><td className="px-4 py-2 font-medium">{stage}</td><td className="px-4 py-2 text-right">{formatTime(value)}</td><td className="px-4 py-2 text-right">{totalSeconds ? `${((number(value) / totalSeconds) * 100).toFixed(1)}%` : "N/A"}</td></tr>)}</tbody></table></div> : <p className="text-sm text-gray-500">No stage timing data was recorded.</p>}</div>;
  const codeContent = <div><h3 className="text-lg font-semibold text-gray-700 mb-2">Code Analysis</h3><div className="mb-4 text-gray-600"><p><span className="font-medium">Lines of Code:</span> {formatNumber(codeMetrics.total_lines)}</p><p><span className="font-medium">Files Analyzed:</span> {formatNumber(codeMetrics.file_count)}</p></div><h3 className="text-lg font-semibold text-gray-700 mb-2">Analyzed Files</h3>{analyzedFiles.length ? <div className="max-h-60 overflow-y-auto bg-gray-50 p-2 rounded text-gray-600 text-sm">{Array.isArray(analyzedFiles) && analyzedFiles.map((file, index) => <div key={`${file}-${index}`} className="mb-1">{String(file)}</div>)}</div> : <p className="text-sm text-gray-500">No file list was recorded.</p>}</div>;
  const configKeys = ["analyzer_model", "skeptic_model", "exploiter_model", "generator_model", "context_model"];
  const summaryContent = <div><h3 className="text-lg font-semibold text-gray-700 mb-2">Summary Metrics</h3><div className="mb-4 text-gray-600"><p><span className="font-medium">Tokens per Second:</span> {formatDecimal(derived.tokens_per_second)}</p><p><span className="font-medium">Tokens per Line of Code:</span> {formatDecimal(derived.tokens_per_loc)}</p></div><h3 className="text-lg font-semibold text-gray-700 mb-2">Configuration</h3>{Object.keys(config).length ? <div className="text-sm text-gray-600 bg-gray-50 p-3 rounded">{Array.isArray(configKeys) && configKeys.map((key) => config[key] !== undefined && <div key={key} className="mb-1"><span className="font-medium">{key.replace("_", " ")}:</span> {String(config[key])}</div>)}<div className="mb-1"><span className="font-medium">Use RAG:</span> {config.use_rag ? "Yes" : "No"}</div><div><span className="font-medium">Timestamp:</span> {runInfo.timestamp || "Not recorded"}</div></div> : <p className="text-sm text-gray-500">Run configuration was not included in this response.</p>}</div>;
  const content = { token: tokenContent, time: timeContent, code: codeContent, summary: summaryContent };
  const tabs = [["token", "Token Usage"], ["time", "Time Analysis"], ["code", "Code Data"], ["summary", "Summary"]];
  return <section className="bg-white shadow-md rounded-lg p-4 mb-4"><h2 className="text-xl font-semibold text-gray-800 mb-4">Performance Metrics</h2><div className="flex flex-wrap border-b mb-4">{Array.isArray(tabs) && tabs.map(([key, title]) => <button key={key} className={`px-4 py-2 font-medium ${activeTab === key ? "text-blue-600 border-b-2 border-blue-500" : "text-gray-600"}`} onClick={() => setActiveTab(key)}>{title}</button>)}</div><div className="p-2">{content[activeTab]}</div></section>;
}

export default PerformanceMetricsPanel;
