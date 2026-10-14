import React from "react";
import { Check, Circle, LoaderCircle, ShieldAlert, Sparkles } from "lucide-react";

export const SECURE_GENERATION_STAGES = [
  ["contract_received", "Contract received"],
  ["static_analysis", "Static security analysis"],
  ["security_context", "Building security context"],
  ["vulnerability_analysis", "Analyzing vulnerabilities"],
  ["finding_validation", "Validating findings"],
  ["secure_generation", "Generating secure Solidity"],
  ["generated_validation", "Validating generated code"],
  ["compiler_validation", "Compiler validation"],
  ["security_validation", "Final security validation"],
  ["finalizing_output", "Finalizing secure output"],
];
const REPAIR_STAGE = ["repairing_contract", "Repairing generated contract"];

const stageState = (stage, state) => {
  if (state.failedStage === stage) return "failed";
  if (state.completedStages.includes(stage)) return "complete";
  if (state.currentStage === stage) return "active";
  return "pending";
};

export default function SecureGenerationProgress({ fileName, state, onRetry, onGenerateAnother }) {
  const completed = SECURE_GENERATION_STAGES.filter(([id]) => state.completedStages.includes(id)).length;
  const progress = state.status === "complete" ? 100 : Math.round((completed / SECURE_GENERATION_STAGES.length) * 100);
  const hasFailed = state.status === "failed";

  return (
    <article className={`secure-progress-card ${hasFailed ? "is-failed" : ""}`} aria-labelledby="secure-progress-title">
      <header className="secure-progress-header">
        <span className="secure-progress-kicker">Local AI security pipeline</span>
        <h2 id="secure-progress-title">{hasFailed ? "Generation failed" : state.status === "complete" ? "Secure contract ready" : "Secure contract generation"}</h2>
        <p className="secure-progress-file">{fileName}</p>
        <p className="secure-progress-model"><Sparkles size={15} /> Local AI · Qwen2.5-Coder 7B · Ollama · RAG enabled</p>
      </header>

      <div className="secure-pipeline" aria-label="Secure generation pipeline">
        {[...SECURE_GENERATION_STAGES.slice(0, 7), ...(state.repairAttempted ? [REPAIR_STAGE] : []), ...SECURE_GENERATION_STAGES.slice(7)].map(([id, label]) => {
          const status = stageState(id, state);
          const Icon = status === "complete" ? Check : status === "failed" ? ShieldAlert : status === "active" ? LoaderCircle : Circle;
          return <div className={`secure-stage is-${status}`} key={id}>
            <span className="secure-stage-icon"><Icon size={17} aria-hidden="true" /></span>
            <span>{label}</span>
          </div>;
        })}
      </div>

      <div className="secure-progress-meter" aria-label={`Pipeline progress: ${progress}%`}>
        <div className="secure-progress-meter-label"><span>Pipeline progress</span><strong>{progress}%</strong></div>
        <div className="secure-progress-track"><i style={{ width: `${progress}%` }} /></div>
      </div>

      <section className="secure-activity" aria-live="polite" aria-atomic="true">
        <span>Current activity</span>
        <h3>{state.message || "Preparing secure generation"}</h3>
        <p>{state.detail || "Waiting for the local security pipeline to begin."}</p>
      </section>

      {hasFailed && <div className="secure-progress-actions"><button type="button" onClick={onRetry}>Try again</button><button type="button" className="secondary" onClick={onGenerateAnother}>Choose another file</button></div>}
    </article>
  );
}
