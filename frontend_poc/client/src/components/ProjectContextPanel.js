import React, { useState, useEffect, useMemo, useRef } from 'react';
import mermaid from 'mermaid';

const asArray = (value) => (Array.isArray(value) ? value : []);
const asObject = (value) =>
  value && typeof value === 'object' && !Array.isArray(value) ? value : {};

const formatListItem = (item) => {
  if (typeof item === 'string' || typeof item === 'number') return String(item);
  if (!item || typeof item !== 'object') return String(item ?? '');

  const title = item.vulnerability_type || item.type || item.title || item.name;
  const description = item.description || item.reasoning || item.details || item.message;
  const summary = [title, description]
    .filter((value) => typeof value === 'string' && value.trim())
    .join(': ');

  return summary || JSON.stringify(item);
};

const relationshipPattern = /^(\w+)\s+(?:inherits from|imports|uses|implements|extends|depends on|interacts with|calls)\s+(\w+)/i;

const buildFallbackDiagram = (contractDetails, contractFiles, dependencies) => {
  const details = contractDetails.length
    ? contractDetails
    : contractFiles.map((file) => ({ name: String(file).split(/[\\/]/).pop().replace(/\.sol$/i, '') }));
  const names = [...new Set(details.map((detail) => detail?.name).filter(Boolean))];
  const ids = new Map(names.map((name, index) => [name, `contract_${index}`]));
  const lines = ['graph TD'];

  names.forEach((name) => lines.push(`${ids.get(name)}["${String(name).replace(/"/g, "'")}"]`));
  dependencies.forEach((dependency) => {
    if (typeof dependency !== 'string') return;
    const match = dependency.match(relationshipPattern);
    if (match && ids.has(match[1])) {
      if (!ids.has(match[2])) {
        const targetId = `contract_${ids.size}`;
        ids.set(match[2], targetId);
        lines.push(`${targetId}["${String(match[2]).replace(/"/g, "'")}"]`);
      }
      lines.push(`${ids.get(match[1])} --> ${ids.get(match[2])}`);
    }
  });
  // Mermaid requires at least one node.  This also gives a clear, non-crashing
  // result when an incomplete context payload reaches the diagram tab.
  if (names.length === 0) lines.push('empty["No contract relationships found"]');
  return lines.join('\n');
};

const ProjectContextPanel = ({ contextData }) => {
  const [activeTab, setActiveTab] = useState('insights');
  const mermaidRef = useRef(null);
  const renderId = useRef(`project-context-diagram-${Math.random().toString(36).slice(2)}`);
  const [diagramError, setDiagramError] = useState('');

  useEffect(() => {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'default',
      securityLevel: 'strict',
      flowchart: {
        htmlLabels: false,
        curve: 'basis'
      }
    });
  }, []);
  
  // If no data, show placeholder
  const safeContextData = asObject(contextData);

  // Extract data from context
  const { 
    insights: rawInsights,
    dependencies: rawDependencies,
    vulnerabilities: rawVulnerabilities,
    recommendations: rawRecommendations,
    important_functions: rawImportantFunctions,
    contract_files: rawContractFiles,
    contract_details: rawContractDetails,
    mermaid_diagram = '',
    stats: rawStats
  } = safeContextData;
  const insights = asArray(rawInsights);
  const dependencies = asArray(rawDependencies);
  const vulnerabilities = asArray(rawVulnerabilities);
  const recommendations = asArray(rawRecommendations);
  const important_functions = asArray(rawImportantFunctions);
  const contract_files = asArray(rawContractFiles);
  const contract_details = asArray(rawContractDetails);
  const stats = asObject(rawStats);
  
  // Function to render list items with tailwind styling
  const renderList = (items, icon) => {
    if (!Array.isArray(items) || items.length === 0) {
      return <div className="text-gray-500 italic p-3">No items found</div>;
    }
    
    return (
      <ul className="divide-y">
        {Array.isArray(items) && items.map((item, index) => (
          <li key={index} className="py-3 px-2 hover:bg-blue-50">
            <div className="flex items-start">
              <div className="flex-shrink-0 text-blue-500 mr-2">
                {icon || '•'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-800">{formatListItem(item)}</p>
              </div>
            </div>
          </li>
        ))}
      </ul>
    );
  };
  
  const fallbackDefinition = useMemo(
    () => buildFallbackDiagram(contract_details, contract_files, dependencies),
    [contract_details, contract_files, dependencies]
  );
  const diagramDefinition = typeof mermaid_diagram === 'string' && mermaid_diagram.trim()
    ? mermaid_diagram.trim()
    : fallbackDefinition;

  useEffect(() => {
    if (activeTab !== 'diagram' || !mermaidRef.current || !diagramDefinition) return undefined;
    let cancelled = false;
    setDiagramError('');
    mermaidRef.current.innerHTML = '';

    const renderDiagram = async (definition, suffix) => {
      const { svg, bindFunctions } = await mermaid.render(`${renderId.current}-${suffix}`, definition);
      if (cancelled || !mermaidRef.current) return;
      mermaidRef.current.innerHTML = svg;
      bindFunctions?.(mermaidRef.current);
    };

    (async () => {
      try {
        await renderDiagram(diagramDefinition, 'primary');
      } catch (primaryError) {
        // LLM output is optional and may be syntactically invalid.  The source
        // derived graph is deterministic and covers inheritance/import edges.
        console.error('Contract diagram rendering failed.', { primaryError, diagramDefinition });
        if (diagramDefinition === fallbackDefinition) throw primaryError;
        try {
          await renderDiagram(fallbackDefinition, 'fallback');
          console.warn('Rendered source-derived contract diagram after Mermaid rejected LLM output.', {
            contract_details,
            dependencies,
            generatedMermaid: fallbackDefinition,
          });
        } catch (fallbackError) {
          console.error('Source-derived contract diagram rendering also failed.', { fallbackError, fallbackDefinition });
          throw fallbackError;
        }
      }
    })().catch(() => {
      if (!cancelled) setDiagramError('Unable to render the contract diagram. Please review the project relationships and try again.');
    });
    return () => { cancelled = true; };
  }, [activeTab, diagramDefinition, fallbackDefinition, contract_details, dependencies]);

  if (Object.keys(safeContextData).length === 0) {
    return (
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Project Context Analysis</h2>
        <div className="p-4 text-center text-gray-500">
          No contract relationship data available
        </div>
      </div>
    );
  }
  
  // Tab configuration
  const tabs = [
    { id: 'insights', label: 'Insights', icon: '💡', count: insights.length },
    { id: 'dependencies', label: 'Dependencies', icon: '🔄', count: dependencies.length },
    { id: 'vulnerabilities', label: 'Context Risk Flags', icon: '⚠️', count: vulnerabilities.length },
    { id: 'recommendations', label: 'Recommendations', icon: '✅', count: recommendations.length },
    { id: 'functions', label: 'Key Functions', icon: '🔑', count: important_functions.length },
    { id: 'diagram', label: 'Contract Diagram', icon: '📊', count: '' },
  ];
  
  return (
    <div className="bg-white p-6 rounded-lg shadow-md mb-6 border border-gray-100">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold">Project Context Analysis</h2>
        <div className="text-sm text-gray-500">
          {stats.total_contracts || 0} contracts analyzed
        </div>
      </div>
      
      {/* Stats summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <div className="bg-blue-50 p-3 rounded-md border border-blue-100">
          <div className="text-sm text-blue-700">Contracts</div>
          <div className="text-xl font-semibold">{stats.total_contracts || 0}</div>
        </div>
        <div className="bg-green-50 p-3 rounded-md border border-green-100">
          <div className="text-sm text-green-700">Dependencies</div>
          <div className="text-xl font-semibold">{stats.total_relationships || dependencies.length || 0}</div>
        </div>
        <div className="bg-red-50 p-3 rounded-md border border-red-100">
          <div className="text-sm text-red-700">Context Risk Flags</div>
          <div className="text-xl font-semibold">{stats.total_vulnerabilities || vulnerabilities.length || 0}</div>
        </div>
        <div className="bg-purple-50 p-3 rounded-md border border-purple-100">
          <div className="text-sm text-purple-700">Recommendations</div>
          <div className="text-xl font-semibold">{stats.total_recommendations || recommendations.length || 0}</div>
        </div>
      </div>
      
      {/* Tabs */}
      <div className="border-b border-gray-200 mb-4">
        <nav className="flex -mb-px space-x-6 overflow-x-auto pb-1">
          {Array.isArray(tabs) && tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                py-2 px-1 border-b-2 font-medium text-sm whitespace-nowrap
                ${activeTab === tab.id 
                  ? 'border-blue-500 text-blue-600' 
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}
              `}
            >
              <span className="mr-1">{tab.icon}</span>
              {tab.label}
              <span className="ml-1 text-xs rounded-full bg-gray-100 px-2 py-0.5">{tab.count}</span>
            </button>
          ))}
        </nav>
      </div>
      
      {/* Tab content */}
      <div className="h-64 overflow-y-auto border rounded-md">
        {activeTab === 'insights' && renderList(insights, '💡')}
        {activeTab === 'dependencies' && renderList(dependencies, '🔄')}
        {activeTab === 'vulnerabilities' && renderList(vulnerabilities, '⚠️')}
        {activeTab === 'recommendations' && renderList(recommendations, '✅')}
        {activeTab === 'functions' && renderList(important_functions, '🔑')}
        {activeTab === 'diagram' && (
          <div className="h-full p-3">
            {contract_files.length > 0 || contract_details.length > 0 || mermaid_diagram ? (
              <div className="mermaid-container h-full overflow-auto">
                {diagramError ? <div className="text-red-700 p-3" role="alert">{diagramError}</div> : <div ref={mermaidRef} />}
              </div>
            ) : (
              <div className="text-gray-500 italic p-3">No contracts available for diagram</div>
            )}
          </div>
        )}
      </div>
      
      {/* Contract files list */}
      {contract_files.length > 0 && (
        <div className="mt-5">
          <h3 className="text-sm font-medium text-gray-700 mb-2">Analyzed Contracts:</h3>
          <div className="flex flex-wrap gap-2">
            {Array.isArray(contract_files) && contract_files.map((file, index) => (
              <span key={index} className="text-xs bg-gray-100 text-gray-800 px-2 py-1 rounded">
                {file}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ProjectContextPanel;
