import React, { useState } from "react";

const asArray = (value) => (Array.isArray(value) ? value : []);
const normalizeCategories = (value) =>
  Array.isArray(value) ? value : value ? [value] : [];
const displayCategory = (category) => {
  if (typeof category === "string" || typeof category === "number") {
    return String(category);
  }

  try {
    return JSON.stringify(category) || "Unknown category";
  } catch {
    return "Unknown category";
  }
};

// Component to show RAG details
const RAGDetailsPanel = ({ details = [] }) => {
  const [expandedItem, setExpandedItem] = useState(null);
  const items = Array.isArray(details)
    ? details.filter((item) => item && typeof item === "object")
    : [];
  
  if (items.length === 0) return null;
  
  return (
    <div className="mt-4 p-4 bg-indigo-50 border border-indigo-200 rounded-md">
      <h3 className="text-lg font-semibold text-indigo-800 mb-3">
        Retrieved Similar Vulnerabilities ({items.length})
      </h3>
      <div className="space-y-3">
        {Array.isArray(items) && items.map((item, index) => {
          const categories = normalizeCategories(item.vuln_categories);

          return (
          <div key={index} className="bg-white border border-indigo-100 rounded-md overflow-hidden">
            <div 
              className="flex items-center justify-between p-3 cursor-pointer bg-indigo-50 hover:bg-indigo-100"
              onClick={() => setExpandedItem(expandedItem === index ? null : index)}
            >
              <div>
                <span className="font-medium text-indigo-700">
                  {item.filename}
                </span>
                <span className="text-xs text-indigo-600 ml-2">
                  (Lines {item.lines_range})
                </span>
              </div>
              <div className="flex items-center">
                <div className="flex space-x-1 mr-2">
                  {categories.length > 0 ? (
                    Array.isArray(categories) && categories.map((cat, i) => (
                      <span key={i} className="px-2 py-1 bg-red-100 text-red-800 text-xs rounded">
                        {displayCategory(cat)}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-gray-500">No vulnerability categories</span>
                  )}
                </div>
                <svg 
                  className={`w-5 h-5 text-indigo-500 transform transition-transform ${expandedItem === index ? 'rotate-180' : ''}`} 
                  fill="none" 
                  stroke="currentColor" 
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>
            {expandedItem === index && (
              <div className="p-3 border-t border-indigo-100">
                <pre className="text-xs bg-gray-50 p-3 rounded overflow-auto max-h-60 font-mono">
                  {item.content_preview}
                </pre>
              </div>
            )}
          </div>
          );
        })}
      </div>
    </div>
  );
};

const AgentVisualizer = ({ activeAgent, status, completedAgents = [], agentDetails = {}, ragDetails = [] }) => {
  const completedAgentList = asArray(completedAgents);
  const ragDetailList = asArray(ragDetails);
  const safeAgentDetails = agentDetails && typeof agentDetails === "object" ? agentDetails : {};
  // Define all steps in the workflow
  const workflowSteps = [
    {
      id: "contract",
      label: "Smart Contract",
      description: "Input smart contract ready for analysis",
    },
    {
      id: "static_analyzer",
      label: "Static Analyzer",
      description: "Running static analysis tools",
    },
    {
      id: "project_context_llm",
      label: "Context Analysis",
      description: "Analyzing inter-contract relationships",
    },
    {
      id: "analyzer",
      label: "Analyzer Agent",
      description: "Detecting potential vulnerabilities",
    },
    {
      id: "skeptic",
      label: "Skeptic Agent",
      description: "Verifying vulnerability validity",
    },
    {
      id: "exploiter",
      label: "Exploiter Agent",
      description: "Creating exploit plans",
    },
    {
      id: "generator",
      label: "Generator Agent",
      description: "Generating proof-of-concept code",
    },
    {
      id: "runner",
      label: "Runner Agent",
      description: "Testing and fixing exploits",
    },
    {
      id: "results",
      label: "Analysis Results",
      description: "Final vulnerability analysis completed",
    },
  ];

  // Helper to determine if a step is completed
  const isStepCompleted = (stepId) => {
    return status === "completed" || completedAgentList.includes(stepId);
  };

  // Helper to determine the current step index
  const getCurrentStepIndex = () => {
    if (status === "completed") return workflowSteps.length - 1;
    if (status !== "analyzing") return -1;

    // If there's an active agent, use its index
    if (activeAgent) {
      const activeIndex = workflowSteps.findIndex(
        (step) => step.id === activeAgent,
      );
      if (activeIndex >= 0) return activeIndex;
    }

    // If no active agent but there are completed agents, return the index after the last completed one
    if (completedAgentList.length > 0) {
      // Find the maximum index of any completed agent
      const completedIndices = Array.isArray(completedAgentList)
        ? completedAgentList
            .map((agent) => workflowSteps.findIndex((step) => step.id === agent))
            .filter((index) => index >= 0)
        : [];

      if (completedIndices.length > 0) {
        return Math.max(...completedIndices) + 1;
      }
    }

    // Default to the first step
    return 0;
  };

  const currentStepIndex = getCurrentStepIndex();

  // Debug output to help troubleshoot
  console.log("Step Visualization:", {
    activeAgent,
    status,
    completedAgents,
    currentStepIndex,
  });

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-xl font-semibold mb-6">Analysis Workflow</h2>

      <div className="overflow-hidden">
        {/* Workflow status overview */}
        <div className="mb-6 relative">
          <div className="h-2.5 bg-gray-200 rounded-full">
            {status === "analyzing" && (
              <div
                className="h-full bg-gradient-to-r from-blue-400 to-blue-600 rounded-full transition-all duration-500"
                style={{
                  width: `${((currentStepIndex + 1) / workflowSteps.length) * 100}%`,
                }}
              ></div>
            )}
            {status === "completed" && (
              <div className="h-full bg-gradient-to-r from-green-400 to-green-600 rounded-full w-full"></div>
            )}
          </div>

          <div className="flex justify-between mt-2 text-xs text-gray-500">
            <span>Start</span>
            <span>In Progress</span>
            <span>Complete</span>
          </div>
        </div>

        {/* Step list */}
        <div className="space-y-4">
          {Array.isArray(workflowSteps) && workflowSteps.map((step, index) => {
            // Determine step status
            let stepStatus = "pending";
            if (isStepCompleted(step.id)) {
              stepStatus = "completed";
            } else if (activeAgent === step.id) {
              stepStatus = "active";
            } else if (status === "analyzing" && index === currentStepIndex) {
              stepStatus = "active";
            }

            // Set styling based on status
            const bgColor =
              stepStatus === "active"
                ? "bg-blue-50 border-blue-200"
                : stepStatus === "completed"
                  ? "bg-green-50 border-green-200"
                  : "bg-gray-50 border-gray-200";

            const iconColor =
              stepStatus === "active"
                ? "bg-blue-500 text-white"
                : stepStatus === "completed"
                  ? "bg-green-500 text-white"
                  : "bg-gray-300 text-gray-500";

            const textColor =
              stepStatus === "active"
                ? "text-blue-700"
                : stepStatus === "completed"
                  ? "text-green-700"
                  : "text-gray-500";

            return (
              <div
                key={step.id}
                className={`flex items-center p-4 border rounded-md ${bgColor} transition-all duration-300 hover:shadow-md`}
              >
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center mr-3 ${iconColor}`}
                >
                  {stepStatus === "completed" ? (
                    <svg
                      className="w-5 h-5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="2"
                        d="M5 13l4 4L19 7"
                      ></path>
                    </svg>
                  ) : stepStatus === "active" ? (
                    <svg
                      className="w-5 h-5 animate-pulse"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="2"
                        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                      ></path>
                    </svg>
                  ) : (
                    <span>{index + 1}</span>
                  )}
                </div>

                <div className="w-full">
                  <div className={`font-medium ${textColor}`}>{step.label}</div>
                  <div className="text-sm text-gray-500">
                    {safeAgentDetails[step.id]?.detail || step.description}
                  </div>
                  {safeAgentDetails[step.id]?.status && stepStatus === "active" && (
                    <div className="mt-1 text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded">
                      {safeAgentDetails[step.id].status}
                    </div>
                  )}
                  {safeAgentDetails[step.id]?.result && stepStatus === "completed" && (
                    <div className="mt-1 text-xs bg-green-50 text-green-700 px-2 py-1 rounded">
                      {safeAgentDetails[step.id].result}
                    </div>
                  )}
                </div>

                {stepStatus === "active" && (
                  <div className="ml-auto">
                    <div className="animate-spin h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Current activity indicator */}
      {status === "analyzing" && activeAgent && (
        <div className="mt-6 p-3 bg-blue-50 border border-blue-200 rounded-md">
          <div className="flex items-center mb-2">
            <div className="animate-pulse mr-3">
              <svg
                className="w-5 h-5 text-blue-500"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z"
                  clipRule="evenodd"
                ></path>
              </svg>
            </div>
            <div>
              <span className="font-medium text-blue-700">Current activity:</span>{" "}
              <span className="text-blue-600">
                {safeAgentDetails[activeAgent]?.status ||
                  (activeAgent === "static_analyzer"
                    ? "Running static analysis"
                    : activeAgent === "analyzer"
                      ? "Analyzing contract for vulnerabilities"
                      : activeAgent === "skeptic"
                        ? "Verifying vulnerability validity"
                        : activeAgent === "exploiter"
                          ? "Creating exploit plan"
                          : activeAgent === "generator"
                            ? "Generating PoC code"
                            : activeAgent === "runner"
                              ? "Running and fixing exploit"
                              : "Processing...")}
              </span>
            </div>
          </div>
          
          {/* Detailed status */}
          {safeAgentDetails[activeAgent]?.detail && (
            <div className="ml-8 text-sm text-blue-600 border-l-2 border-blue-200 pl-3">
              {safeAgentDetails[activeAgent].detail}
            </div>
          )}
        </div>
      )}
      
      {/* Display RAG details if available and the analyzer agent is active or complete */}
      {ragDetailList.length > 0 && (activeAgent === "analyzer" || completedAgentList.includes("analyzer")) && (
        <RAGDetailsPanel details={ragDetailList} />
      )}

      {/* Success indicator */}
      {status === "completed" && (
        <div className="mt-6 p-3 bg-green-50 border border-green-200 rounded-md flex items-center">
          <svg
            className="w-5 h-5 text-green-500 mr-3"
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path
              fillRule="evenodd"
              d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
              clipRule="evenodd"
            ></path>
          </svg>
          <span className="font-medium text-green-700">
            Analysis completed successfully
          </span>
        </div>
      )}

      {/* Debug info for development - comment out in production */}
      {process.env.NODE_ENV === "development" && (
        <div className="mt-4 p-2 bg-gray-100 text-xs font-mono">
          <div>Active Agent: {activeAgent || "none"}</div>
          <div>Status: {status}</div>
          <div>Completed Agents: {completedAgentList.join(", ") || "none"}</div>
          <div>Current Step Index: {currentStepIndex}</div>
        </div>
      )}
    </div>
  );
};

export default AgentVisualizer;
