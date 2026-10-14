import React, { useEffect, useRef, useState } from "react";
import { io } from "socket.io-client";
import { Download, FileCode2, FolderOpen, RotateCcw, ShieldCheck, UploadCloud } from "lucide-react";
import { fetchSecureGeneration, generateSecureContract } from "../services/api";
import SecureGenerationProgress from "./SecureGenerationProgress";

const API_ORIGIN = "http://localhost:3000";
const initialGenerationState = () => ({ generationId: null, currentStage: "contract_received", completedStages: [], failedStage: null, repairAttempted: false, message: "Preparing secure generation", detail: "Connecting to the local security pipeline.", status: "idle" });
const newId = () => window.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;

const SecureGeneratorPage = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [fileError, setFileError] = useState("");
  const [result, setResult] = useState(null);
  const [generationState, setGenerationState] = useState(initialGenerationState);
  const fileInputRef = useRef(null);
  const socketRef = useRef(null);
  const activeGenerationRef = useRef(null);
  const isGenerating = generationState.status === "generating";

  useEffect(() => {
    socketRef.current = io(API_ORIGIN);
    return () => socketRef.current?.disconnect();
  }, []);

  useEffect(() => {
    const socket = socketRef.current;
    const generationId = generationState.generationId;
    if (!socket || !generationId || !["generating", "complete"].includes(generationState.status)) return undefined;
    const onProgress = (event) => {
      if (event?.generation_id !== activeGenerationRef.current) return;
      setGenerationState((previous) => {
        const completedStages = Array.isArray(event.completed_stages) ? event.completed_stages : event.status === "complete" && event.stage !== "complete" && !previous.completedStages.includes(event.stage)
          ? [...previous.completedStages, event.stage] : previous.completedStages;
        return { ...previous, currentStage: event.stage, completedStages, failedStage: event.status === "failed" ? event.stage : null, repairAttempted: previous.repairAttempted || event.stage === "repairing_contract", message: event.message, detail: event.detail, status: event.status === "failed" ? "failed" : previous.status };
      });
    };
    socket.on("secure_generation_progress", onProgress);
    return () => socket.off("secure_generation_progress", onProgress);
  }, [generationState.generationId, generationState.status]);

  useEffect(() => {
    if (generationState.status !== "generating" || !generationState.generationId) return undefined;
    const poll = async () => {
      try {
        const response = await fetchSecureGeneration(generationState.generationId);
        if (activeGenerationRef.current !== generationState.generationId) return;
        if (response.data.status === "completed") {
          setResult(response.data.result);
          setGenerationState((state) => ({ ...state, status: "complete", currentStage: "complete", completedStages: state.completedStages }));
        } else if (response.data.status === "error") {
          setGenerationState((state) => ({ ...state, status: "failed", failedStage: state.currentStage, message: "Generation failed", detail: response.data.error || "The secure contract could not be generated." }));
        }
      } catch (error) { /* Socket.IO remains the primary progress channel; polling is reconnect recovery. */ }
    };
    const interval = window.setInterval(poll, 3000);
    return () => window.clearInterval(interval);
  }, [generationState.generationId, generationState.status]);

  const selectFile = (file) => {
    if (!file || isGenerating) return;
    if (!file.name.toLowerCase().endsWith(".sol")) return setFileError("Please choose a Solidity (.sol) file.");
    setSelectedFile(file); setFileError("");
  };
  const handleFileChange = (event) => { selectFile(event.target.files?.[0]); event.target.value = ""; };
  const handleDrop = (event) => { event.preventDefault(); setIsDragging(false); selectFile(event.dataTransfer.files?.[0]); };

  const handleGenerate = async () => {
    if (!selectedFile || isGenerating) return;
    const generationId = newId();
    activeGenerationRef.current = generationId;
    setFileError(""); setResult(null);
    setGenerationState({ ...initialGenerationState(), generationId, status: "generating" });
    try {
      socketRef.current?.emit("join_secure_generation", { generation_id: generationId });
      const formData = new FormData(); formData.append("file", selectedFile); formData.append("generation_id", generationId);
      await generateSecureContract(formData);
    } catch (error) {
      setGenerationState((state) => ({ ...state, status: "failed", failedStage: state.currentStage, message: "Generation failed", detail: error.response?.data?.error || error.message || "Unable to start secure contract generation." }));
    }
  };
  const generateAnother = () => { activeGenerationRef.current = null; setResult(null); setSelectedFile(null); setFileError(""); setIsDragging(false); setGenerationState(initialGenerationState()); };

  if (result && generationState.status !== "complete") return (
    <section className="placeholder-page"><div className="placeholder-page-heading"><h1>🛠️ Secure Contract Generator</h1><p>Generate secure versions of vulnerable Solidity smart contracts using AI.</p></div><article className="placeholder-card"><div className="upload-section-heading"><div className="upload-tab"><ShieldCheck size={25} /> Security Summary</div><p>{result.security_summary}</p></div><div className="feature-grid"><article className="feature-card"><FileCode2 size={28} className="feature-icon blue" /><div><h3>Vulnerabilities Detected</h3><p>{result.vulnerabilities_detected}</p></div></article><article className="feature-card"><ShieldCheck size={28} className="feature-icon cyan" /><div><h3>Validation Status</h3><p>{result.validation_status}</p></div></article><article className="feature-card"><ShieldCheck size={28} className="feature-icon emerald" /><div><h3>Compile Status</h3><p>{result.compile_status}</p></div></article>{result.reverification && <article className="feature-card"><ShieldCheck size={28} className="feature-icon emerald" /><div><h3>Slither Findings</h3><p>{result.reverification.original_finding_count} before → {result.reverification.generated_finding_count} after</p><small>{result.reverification.resolved_findings.length} resolved</small></div></article>}</div><div className="paste-code-actions"><button type="button" onClick={() => window.location.assign(`${API_ORIGIN}${result.download_url}`)}><Download size={18} /> Download Secure Contract</button><button type="button" onClick={generateAnother}><RotateCcw size={18} /> Generate Another</button></div></article></section>
  );

  if (["generating", "complete", "failed"].includes(generationState.status)) return <section className="placeholder-page"><SecureGenerationProgress fileName={selectedFile?.name || "Solidity contract"} state={generationState} onRetry={handleGenerate} onGenerateAnother={generateAnother} />{generationState.status === "complete" && <div className="secure-progress-actions success-actions"><button type="button" onClick={() => setGenerationState((state) => ({ ...state, status: "result" }))}>View Secure Contract</button><button type="button" className="secondary" onClick={() => window.location.assign(`${API_ORIGIN}${result?.download_url}`)}><Download size={17} /> Download Secure Contract</button></div>}</section>;

  return <section className="placeholder-page"><div className="placeholder-page-heading"><h1>🛠️ Secure Contract Generator</h1><p>Generate secure versions of vulnerable Solidity smart contracts using AI.</p></div><article className="placeholder-card"><div className="upload-section-heading"><div className="upload-tab"><UploadCloud size={25} /> Upload Solidity Contract</div><p>Upload a Solidity contract to prepare it for secure contract generation.</p></div><div className={`upload-dropzone ${isDragging ? "is-dragging" : ""}`} onClick={() => fileInputRef.current?.click()} onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setIsDragging(false); }} onDrop={handleDrop} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInputRef.current?.click(); } }}><input ref={fileInputRef} className="hidden" type="file" accept=".sol" onChange={handleFileChange} /><FileCode2 className="upload-icon" aria-hidden="true" /><p className="upload-title">Drag & Drop your .sol file here</p><p className="upload-action">or</p><button className="browse-files-button" type="button" onClick={(event) => { event.stopPropagation(); fileInputRef.current?.click(); }}><FolderOpen size={21} /> Choose .sol File</button>{selectedFile && <p className="upload-file">Selected: {selectedFile.name}</p>}</div>{fileError && <p className="upload-error" role="alert">{fileError}</p>}<button className="start-analysis-button" type="button" disabled={!selectedFile} onClick={handleGenerate}><ShieldCheck size={27} /><span>Generate Secure Contract</span></button></article></section>;
};

export default SecureGeneratorPage;
