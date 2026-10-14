import React, { useState, useEffect, useRef } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Header from "./components/Header";
import AnimatedGearBackground from "./components/AnimatedGearBackground";
import VulnerabilitiesPage from "./components/VulnerabilitiesPage";
import SecureGeneratorPage from "./components/SecureGeneratorPage";
import ContractInput from "./components/ContractInput";
import AgentVisualizer from "./components/AgentVisualizer";
import VulnerabilitiesPanel from "./components/VulnerabilitiesPanel";
import ExploitsPanel from "./components/ExploitsPanel";
import ProjectContextPanel from "./components/ProjectContextPanel";
import PerformanceMetricsPanel from "./components/PerformanceMetricsPanel";
import ErrorBoundary from "./components/ErrorBoundary";
import { io } from "socket.io-client";
import {
  fetchContractStatus,
  fetchContractResults,
  startAnalysis,
} from "./services/api";
import "./App.css";

// Initialize socket.io client - make sure port matches your backend
const socket = io("http://localhost:3000");
const asObject = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : null;

const validateCompletedResponse = (payload) => {
  const response = asObject(payload);
  const results = asObject(response?.results);
  if (!results) throw new Error("The server returned an incomplete analysis result.");
  return { results, performanceMetrics: asObject(response.performance_metrics) };
};

const getProjectContext = (results) => asObject(results?.project_context);

function App() {
  const [currentJob, setCurrentJob] = useState(null);
  const [jobStatus, setJobStatus] = useState("idle");
  const [analysisResults, setAnalysisResults] = useState(null);
  const [activeAgent, setActiveAgent] = useState(null);
  const [completedAgents, setCompletedAgents] = useState([]);
  const [agentDetails, setAgentDetails] = useState({});
  const [ragDetails, setRagDetails] = useState([]);
  const [projectContextData, setProjectContextData] = useState({});
  const [performanceMetrics, setPerformanceMetrics] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);
  const analysisOptions = {
  context_model: "ollama",
  analyzer_model: "ollama",
  skeptic_model: "ollama",
  exploiter_model: "ollama",
  generator_model: "ollama",
  auto_run: true,
  max_retries: 3,
  use_rag: true,
  skip_poc_generation: false,
  export_markdown: false,
  };

  // Keep a reference to currentJob that won't cause effect hook to re-run
  const currentJobRef = useRef(null);

  useEffect(() => {
    currentJobRef.current = currentJob;
  }, [currentJob]);

  // Connect to Socket.io for real-time updates
  useEffect(() => {
    console.log("Setting up socket listeners");

    // Set up socket event listeners
    const onConnect = () => {
      console.log("Connected to server");
    };

    const onAnalysisStarted = (data) => {
      console.log("Analysis started event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setJobStatus("analyzing");
      }
    };

    const onAgentActive = (data) => {
      console.log("Agent active event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setActiveAgent(data.agent);
      }
    };

    const onAgentComplete = (data) => {
      console.log("Agent complete event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        const agent = data.agent;

        // Add to completed agents list
        setCompletedAgents((prev) => {
          if (!prev.includes(agent)) {
            return [...prev, agent];
          }
          return prev;
        });

        // Save the result if provided
        if (data.result) {
          setAgentDetails((prev) => ({
            ...prev,
            [agent]: {
              ...prev[agent],
              result: data.result,
              timestamp: new Date().toISOString(),
            },
          }));
        }

        // If this agent was active, clear it
        setActiveAgent((prev) => (prev === agent ? null : prev));
      }
    };

    const onAnalysisComplete = async (data) => {
      console.log("Analysis complete event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setJobStatus("completed");
        setActiveAgent(null);

        // Fetch full results
        try {
          const completed = validateCompletedResponse((await fetchContractResults(data.job_id)).data);
          setAnalysisResults(completed.results);
          const completedContext = getProjectContext(completed.results);
          if (completedContext) setProjectContextData(completedContext);
          
          // Set performance metrics if available
          setPerformanceMetrics(asObject(data.performance_metrics) || completed.performanceMetrics);
          setAnalysisError(null);
        } catch (error) {
          console.error("Error fetching results:", error);
          setJobStatus("error");
          setAnalysisError(error.message || "The analysis completed but its results could not be loaded.");
        }
      }
    };

    const onAnalysisError = (data) => {
      console.log("Analysis error event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setJobStatus("error");
        setActiveAgent(null);
        setAnalysisError(data?.error || "Analysis failed on the server.");
      }
    };

    const onContractFetched = (data) => {
      console.log("Contract fetched event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setJobStatus("fetched");
      }
    };

    const onAgentStatus = (data) => {
      console.log("Agent status event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setAgentDetails((prev) => ({
          ...prev,
          [data.agent]: {
            status: data.status,
            detail: data.detail,
            timestamp: new Date().toISOString(),
          },
        }));
      }
    };

    const onRagDetails = (data) => {
      console.log("RAG details event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setRagDetails(data.details || []);
      }
    };
    
    const onProjectContextInsights = (data) => {
      console.log("Project context insights event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setProjectContextData(data.details || {});
      }
    };

    const onContractFetchError = (data) => {
      console.log("Contract fetch error event:", data);
      if (currentJobRef.current?.id === data?.job_id) {
        setJobStatus("error");
        setAnalysisError(data?.error || "The contract could not be fetched.");
      }
    };

    socket.on("connect", onConnect);
    socket.on("analysis_started", onAnalysisStarted);
    socket.on("agent_active", onAgentActive);
    socket.on("agent_complete", onAgentComplete);
    socket.on("agent_status", onAgentStatus);
    socket.on("rag_details", onRagDetails);
    socket.on("project_context_insights", onProjectContextInsights);
    socket.on("analysis_complete", onAnalysisComplete);
    socket.on("analysis_error", onAnalysisError);
    socket.on("contract_fetched", onContractFetched);
    socket.on("contract_fetch_error", onContractFetchError);

    // Clean up on unmount
    return () => {
      console.log("Cleaning up socket listeners");
      socket.off("connect", onConnect);
      socket.off("analysis_started", onAnalysisStarted);
      socket.off("agent_active", onAgentActive);
      socket.off("agent_complete", onAgentComplete);
      socket.off("agent_status", onAgentStatus);
      socket.off("rag_details", onRagDetails);
      socket.off("project_context_insights", onProjectContextInsights);
      socket.off("analysis_complete", onAnalysisComplete);
      socket.off("analysis_error", onAnalysisError);
      socket.off("contract_fetched", onContractFetched);
      socket.off("contract_fetch_error", onContractFetchError);
    };
  }, []); // Empty dependency array to set up only once

  // Poll job status if not completed or error
  useEffect(() => {
    let interval;
    if (
      currentJob &&
      ["uploaded", "fetched", "analyzing"].includes(jobStatus)
    ) {
      interval = setInterval(async () => {
        try {
          const response = await fetchContractStatus(currentJob.id);
          const status = response.data?.status;
          if (!status) throw new Error("The server returned an invalid job status response.");
          setJobStatus(status);

          if (status === "completed") {
            const completed = validateCompletedResponse((await fetchContractResults(currentJob.id)).data);
            setAnalysisResults(completed.results);
            const completedContext = getProjectContext(completed.results);
            if (completedContext) setProjectContextData(completedContext);
            setPerformanceMetrics(completed.performanceMetrics);
            setAnalysisError(null);
            clearInterval(interval);
          } else if (status === "error") {
            setAnalysisError(response.data?.error || "Analysis failed on the server.");
            clearInterval(interval);
          }
        } catch (error) {
          console.error("Error polling job status:", error);
          setJobStatus("error");
          setAnalysisError(error.message || "Unable to retrieve the analysis status.");
          clearInterval(interval);
        }
      }, 5000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [currentJob, jobStatus]);

  const handleContractSubmit = (jobData) => {
    if (!jobData?.id || !jobData?.status) {
      setAnalysisError("The upload response did not include a valid analysis job.");
      return;
    }
    setCurrentJob(jobData);
    setJobStatus(jobData.status);
    setAnalysisResults(null);
    setActiveAgent(null);
    setCompletedAgents([]); // Reset completed agents
    setAgentDetails({}); // Reset agent details
    setRagDetails([]); // Reset RAG details
    setProjectContextData({}); // Reset project context data
    setPerformanceMetrics(null); // Reset performance metrics
    setAnalysisError(null);
  };

  const handleStartAnalysis = async () => {
    if (!currentJob?.id) {
      setAnalysisError("Upload a contract before starting analysis.");
      return;
    }

    try {
      await startAnalysis({
        job_id: currentJob.id,
        ...analysisOptions,
      });
      setJobStatus("analyzing");
      setAnalysisError(null);
    } catch (error) {
      console.error("Error starting analysis:", error);
      setJobStatus("error");
      setAnalysisError(error.response?.data?.error || error.message || "Unable to start analysis.");
    }
  };

  return (
    <Router>
      <div className="app-shell min-h-screen">
        <AnimatedGearBackground />
        <Header />

        <main className="container mx-auto px-4 md:px-6 max-w-7xl">
          <Routes>
            <Route
              path="/"
              element={
                <>
                  <section className="landing-hero">
                    <div className="hero-badge">
                    🧠 RAG-POWERED LOCAL LLM
                    </div>
                    <h1>Smart Contract Vulnerability <span>Analyzer</span></h1>
                    <p>Advanced AI-powered security analysis for Solidity smart contracts</p>
                    <ContractInput
                      onContractSubmit={handleContractSubmit}
                      onStartAnalysis={handleStartAnalysis}
                      isReady={Boolean(currentJob && ["uploaded", "fetched"].includes(jobStatus))}
                      isAnalyzing={jobStatus === "analyzing"}
                    />
                  </section>

                  {currentJob && (
                    <div className="mb-8 analysis-workflow">
                      <AgentVisualizer
                        activeAgent={activeAgent}
                        status={jobStatus}
                        completedAgents={completedAgents}
                        agentDetails={agentDetails}
                        ragDetails={ragDetails}
                      />
                    </div>
                  )}
                  {analysisError && (
                    <section className="mb-8 bg-red-50 border border-red-200 text-red-800 rounded-lg p-4" role="alert">
                      <p className="font-medium">Analysis error</p>
                      <p className="text-sm mt-1">{analysisError}</p>
                      {currentJob && <button className="mt-3 px-3 py-2 rounded bg-red-700 text-white" onClick={handleStartAnalysis}>Retry analysis</button>}
                    </section>
                  )}

                  {/* Show Project Context Panel as soon as data is available */}
                  {Object.keys(projectContextData).length > 0 && (
                    <div className="mb-8">
                      <ProjectContextPanel contextData={projectContextData} />
                    </div>
                  )}
                  
                  {analysisResults && (
                    <div className="grid grid-cols-1 gap-6">
                      <ErrorBoundary message="Vulnerability findings could not be rendered.">
                        <VulnerabilitiesPanel vulnerabilities={Array.isArray(analysisResults.rechecked_vulnerabilities) ? analysisResults.rechecked_vulnerabilities : []} />
                      </ErrorBoundary>
                      <ErrorBoundary message="Proof-of-concept details could not be rendered.">
                        <ExploitsPanel exploits={Array.isArray(analysisResults.generated_pocs) ? analysisResults.generated_pocs : []} />
                      </ErrorBoundary>
                      {performanceMetrics && (
                        <ErrorBoundary message="Performance metrics could not be rendered.">
                          <PerformanceMetricsPanel metrics={performanceMetrics} />
                        </ErrorBoundary>
                      )}
                    </div>
                  )}
                </>
              }
            />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/secure-generator" element={<SecureGeneratorPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
