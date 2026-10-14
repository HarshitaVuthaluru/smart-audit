import React, { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";

const VulnerabilitiesPanel = ({ vulnerabilities }) => {
  const [selectedVulnIndex, setSelectedVulnIndex] = useState(null);
  const items = Array.isArray(vulnerabilities)
    ? vulnerabilities.filter((vulnerability) => vulnerability && typeof vulnerability === "object")
    : [];

  if (items.length === 0) {
    return (
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Vulnerabilities</h2>
        <div className="p-4 text-center text-gray-500">
          No vulnerabilities detected
        </div>
      </div>
    );
  }

  const selectedVuln =
    selectedVulnIndex !== null ? items[selectedVulnIndex] : null;

  // Function to get confidence level class
  const getConfidenceClass = (confidence) => {
    if (confidence >= 0.7) return "bg-red-100 text-red-800 border-red-300";
    if (confidence >= 0.4)
      return "bg-yellow-100 text-yellow-800 border-yellow-300";
    return "bg-green-100 text-green-800 border-green-300";
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-shadow duration-300 border border-gray-100">
      <h2 className="text-xl font-semibold mb-4">Detected Vulnerabilities</h2>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Vulnerability List */}
        <div className="lg:col-span-1 border rounded-md overflow-hidden">
          <div className="bg-gray-50 px-4 py-2 border-b">
            <h3 className="font-medium">
              Vulnerabilities ({items.length})
            </h3>
          </div>
          <div className="divide-y max-h-96 overflow-y-auto">
            {Array.isArray(items) && items.map((vuln, index) => (
              <div
                key={index}
                className={`px-4 py-3 cursor-pointer hover:bg-gray-50 ${selectedVulnIndex === index ? "bg-blue-50" : ""}`}
                onClick={() => setSelectedVulnIndex(index)}
              >
                <div className="flex justify-between items-center">
                  <span className="font-medium">{vuln.vulnerability_type || "Unknown vulnerability"}</span>
                  <span
                    className={`text-xs px-2 py-1 rounded-full ${getConfidenceClass(vuln.skeptic_confidence || 0)}`}
                  >
                    {((vuln.skeptic_confidence || 0) * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="text-sm text-gray-500 truncate mt-1">
                  {Array.isArray(vuln.affected_functions) && vuln.affected_functions.length > 0
                    ? vuln.affected_functions.join(", ")
                    : "No specific functions"}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Details */}
        <div className="lg:col-span-2 border rounded-md">
          {selectedVuln ? (
            <div>
              <div className="bg-gray-50 px-4 py-2 border-b">
                <h3 className="font-medium">
                  {selectedVuln.vulnerability_type || "Unknown vulnerability"}
                </h3>
              </div>
              <div className="p-4 space-y-4 max-h-96 overflow-y-auto">
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-1">
                    Confidence Score
                  </h4>
                  <div className="w-full bg-gray-200 rounded-full h-2.5">
                    <div
                      className={`h-2.5 rounded-full ${selectedVuln.skeptic_confidence >= 0.7 ? "bg-red-600" : selectedVuln.skeptic_confidence >= 0.4 ? "bg-yellow-500" : "bg-green-500"}`}
                      style={{
                        width: `${(selectedVuln.skeptic_confidence || 0) * 100}%`,
                      }}
                    ></div>
                  </div>
                  <div className="text-right text-xs text-gray-500 mt-1">
                    {((selectedVuln.skeptic_confidence || 0) * 100).toFixed(0)}%
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-700">
                    Reasoning
                  </h4>
                  <p className="text-sm text-gray-600 mt-1">
                    {selectedVuln.reasoning || "No reasoning provided"}
                  </p>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-700">
                    Validity Assessment
                  </h4>
                  <p className="text-sm text-gray-600 mt-1">
                    {selectedVuln.validity_reasoning ||
                      "No validity assessment provided"}
                  </p>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-700">
                    Affected Functions
                  </h4>
                  {Array.isArray(selectedVuln.affected_functions) &&
                  selectedVuln.affected_functions.length > 0 ? (
                    <ul className="list-disc pl-5 text-sm text-gray-600 mt-1">
                      {Array.isArray(selectedVuln.affected_functions) && selectedVuln.affected_functions.map((func, idx) => (
                        <li key={idx}>{func}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-gray-500 mt-1">
                      No specific functions identified
                    </p>
                  )}
                </div>

                {selectedVuln.code_snippet && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700">
                      Code Snippet
                    </h4>
                    <div className="mt-1 text-xs">
                      <SyntaxHighlighter
                        language="solidity"
                        style={vscDarkPlus}
                        wrapLines={true}
                        showLineNumbers={true}
                        customStyle={{
                          margin: 0,
                          borderRadius: "0.375rem",
                          maxHeight: "400px",
                          boxShadow:
                            "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)",
                        }}
                      >
                        {selectedVuln.code_snippet}
                      </SyntaxHighlighter>
                    </div>
                  </div>
                )}

                {selectedVuln.exploitation_scenario && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700">
                      Exploitation Scenario
                    </h4>
                    <p className="text-sm text-gray-600 mt-1">
                      {selectedVuln.exploitation_scenario}
                    </p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-gray-500">
              Select a vulnerability to view details
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default VulnerabilitiesPanel;
