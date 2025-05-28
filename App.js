
import React, { useState, useEffect, useCallback } from 'react';
import { ChevronRight, Copy, Save, Download, Languages, Sparkles, Brain, Check, X, AlertCircle, FileText, Clock, Star, Loader2, Trash2 } from 'lucide-react'; // Added Trash2
// Removed type imports: PromptType, Language, Domain, Complexity, OutputLength, SavedPrompt, Translations
import { translations, DEFAULT_LANGUAGE, MIN_RAW_REQUEST_LENGTH, MAX_RAW_REQUEST_LENGTH, DOMAIN_OPTIONS, OUTPUT_LENGTH_OPTIONS } from './constants.js';
import { generateStructuredPromptWithGemini } from './services/geminiService.js';

const App = () => {
  const [language, setLanguage] = useState(DEFAULT_LANGUAGE);
  const [step, setStep] = useState(1);
  const [rawRequest, setRawRequest] = useState('');
  const [promptType, setPromptType] = useState('MVP');
  
  const [analyzedDomain, setAnalyzedDomain] = useState('other');
  const [analyzedComplexity, setAnalyzedComplexity] = useState('simple');
  const [recommendedType, setRecommendedType] = useState('MVP');

  const [selectedDomain, setSelectedDomain] = useState('education');
  const [outputLength, setOutputLength] = useState('medium');
  const [expertRole, setExpertRole] = useState('');
  const [mission, setMission] = useState('');
  const [constraints, setConstraints] = useState('');
  
  const [generatedPrompt, setGeneratedPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [showLibrary, setShowLibrary] = useState(false);
  const [savedPrompts, setSavedPrompts] = useState([]);
  const [notification, setNotification] = useState('');
  
  const t = translations[language];

  useEffect(() => {
    const saved = localStorage.getItem('teachinspire-prompts');
    if (saved) {
      try {
        setSavedPrompts(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to parse saved prompts from localStorage", e);
        localStorage.removeItem('teachinspire-prompts');
      }
    }
  }, []);

  const analyzeUserRequest = useCallback((request) => {
    const educationKeywords = ['cours', 'leçon', 'lesson', 'élève', 'student', 'apprendre', 'learn', 'enseigner', 'teach', 'pédagogie', 'pedagogy'];
    const technicalKeywords = ['code', 'algorithm', 'database', 'api', 'système', 'system', 'technique', 'software', 'hardware', 'network'];
    const creativeKeywords = ['story', 'histoire', 'créer', 'create', 'design', 'art', 'écrire', 'write', 'roman', 'poème', 'scénario'];
    const analysisKeywords = ['analyser', 'analyze', 'rapport', 'report', 'données', 'data', 'évaluer', 'evaluate', 'recherche', 'research'];
    
    const requestLower = request.toLowerCase();
    
    let detectedDomain = 'other';
    if (educationKeywords.some(k => requestLower.includes(k))) detectedDomain = 'education';
    else if (technicalKeywords.some(k => requestLower.includes(k))) detectedDomain = 'technical';
    else if (creativeKeywords.some(k => requestLower.includes(k))) detectedDomain = 'creative';
    else if (analysisKeywords.some(k => requestLower.includes(k))) detectedDomain = 'analysis';
    
    const complexIndicators = ['plusieurs', 'multiple', 'complexe', 'complex', 'détaillé', 'detailed', 'approfondi', 'comprehensive', 'stratégie', 'strategy'];
    const isComplex = complexIndicators.some(k => requestLower.includes(k)) || request.length > 250;
    
    return {
      domain: detectedDomain,
      complexity: isComplex ? 'complex' : 'simple',
      recommendedType: isComplex ? 'AGENTIC' : 'MVP'
    };
  }, []);

  const handleAnalyzeRequest = () => {
    if (rawRequest.length >= MIN_RAW_REQUEST_LENGTH) {
      const analysis = analyzeUserRequest(rawRequest);
      setAnalyzedDomain(analysis.domain);
      setAnalyzedComplexity(analysis.complexity);
      setRecommendedType(analysis.recommendedType);
      setSelectedDomain(analysis.domain); 
      setPromptType(analysis.recommendedType);
      setStep(2);
    }
  };
  
  const handleGeneratePrompt = async () => {
    setIsGenerating(true);
    setStep(4);

    try {
      const result = await generateStructuredPromptWithGemini({
        rawRequest,
        promptType,
        domain: selectedDomain,
        language,
        outputLength,
        expertRole,
        mission,
        constraints,
      });
      setGeneratedPrompt(result);
    } catch (error) {
      console.error("Error in handleGeneratePrompt:", error);
      setGeneratedPrompt(t.generation.error + (error instanceof Error ? ` ${error.message}` : ''));
      showNotification(t.notifications.apiError, 'error');
    } finally {
      setIsGenerating(false);
    }
  };

  const showNotification = (message, type = 'success') => {
    setNotification(message);
    // Add logic for different notification types if styling changes based on type
    // For example, changing the icon or background color of the notification toast
    // For now, 'type' is available if we enhance this later.
    setTimeout(() => setNotification(''), 3000);
  };

  const copyToClipboard = async () => {
    if (!generatedPrompt) return;
    try {
      await navigator.clipboard.writeText(generatedPrompt);
      showNotification(t.notifications.copied, 'success');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      showNotification(t.notifications.copyFailed, 'error');
    }
  };

  const savePrompt = () => {
    if (!generatedPrompt) return;
    const newPromptData = {
      id: Date.now().toString(),
      timestamp: Date.now(),
      rawRequest,
      generatedPrompt,
      type: promptType,
      domain: selectedDomain,
      language
    };
    
    const updatedPrompts = [newPromptData, ...savedPrompts];
    setSavedPrompts(updatedPrompts);
    localStorage.setItem('teachinspire-prompts', JSON.stringify(updatedPrompts));
    showNotification(t.notifications.saved, 'success');
  };

  const exportPrompt = () => {
    if (!generatedPrompt) return;
    const blob = new Blob([generatedPrompt], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `teachinspire-prompt-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const resetForm = () => {
    setStep(1);
    setRawRequest('');
    setGeneratedPrompt('');
    setExpertRole('');
    setMission('');
    setConstraints('');
    setAnalyzedDomain('other');
    setAnalyzedComplexity('simple');
    setRecommendedType('MVP');
    setSelectedDomain('education');
    setOutputLength('medium');
    setPromptType('MVP');
  };

  const loadPromptFromLibrary = (promptData) => {
    setRawRequest(promptData.rawRequest);
    setGeneratedPrompt(promptData.generatedPrompt);
    setPromptType(promptData.type);
    setSelectedDomain(promptData.domain);
    setLanguage(promptData.language);
    setShowLibrary(false);
    setStep(4);
    setIsGenerating(false);
  };

  const handleDeletePrompt = (promptIdToDelete) => {
    const updatedPrompts = savedPrompts.filter(prompt => prompt.id !== promptIdToDelete);
    setSavedPrompts(updatedPrompts);
    localStorage.setItem('teachinspire-prompts', JSON.stringify(updatedPrompts));
    showNotification(t.notifications.deleted, 'success');
  };


  return React.createElement("div", { className: "min-h-screen bg-brand-bg text-brand-text font-inter" },
    React.createElement("header", { className: "bg-brand-card-bg shadow-brand" },
      React.createElement("div", { className: "container mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center" },
        React.createElement("img", {
          src: "https://res.cloudinary.com/ducvoebot/image/upload/v1747991665/Teachinspire_logo_transparent_yjt3uf.png",
          alt: "Teachinspire Logo",
          className: "h-12 md:h-16 w-auto"
        }),
        React.createElement("button", {
          onClick: () => setLanguage(language === 'fr' ? 'en' : 'fr'),
          className: "flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-brand-primary-accent/10 text-brand-primary-accent transition-colors",
          "aria-label": language === 'fr' ? 'Switch to English' : 'Passer au Français'
        },
          React.createElement(Languages, { className: "w-5 h-5" }),
          React.createElement("span", { className: "font-medium" }, language.toUpperCase())
        )
      )
    ),
    React.createElement("main", { className: "container mx-auto px-4 sm:px-6 lg:px-8 py-8 max-w-3xl" },
      React.createElement("div", { className: "text-center mb-10" },
        React.createElement("h1", { className: "font-playfair text-3xl md:text-4xl font-bold text-brand-text mb-3" }, t.app.title),
        React.createElement("p", { className: "text-brand-primary-accent text-lg" }, t.app.subtitle)
      ),
      step === 1 && React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8" },
        React.createElement("label", { htmlFor: "rawRequestInput", className: "block text-xl font-semibold text-brand-text mb-4 pb-2 border-b-2 border-brand-primary-accent/50" }, t.input.placeholder),
        React.createElement("textarea", {
          id: "rawRequestInput",
          value: rawRequest,
          onChange: (e) => setRawRequest(e.target.value),
          placeholder: language === 'fr' ? "Exemple: Je veux créer un cours interactif sur les énergies renouvelables pour des lycéens..." : "Example: I want to create an interactive lesson about renewable energy for high school students...",
          className: "w-full h-40 p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none resize-none font-inter text-base",
          maxLength: MAX_RAW_REQUEST_LENGTH
        }),
        React.createElement("div", { className: "flex flex-col sm:flex-row justify-between items-center mt-4 space-y-3 sm:space-y-0" },
          React.createElement("span", { className: `text-sm ${rawRequest.length < MIN_RAW_REQUEST_LENGTH && rawRequest.length > 0 ? 'text-brand-error' : 'text-brand-muted-text'}` },
            rawRequest.length, "/", MAX_RAW_REQUEST_LENGTH, " ", t.input.charCount,
            rawRequest.length > 0 && rawRequest.length < MIN_RAW_REQUEST_LENGTH && React.createElement("span", { className: "ml-2" }, "(", t.input.minCharWarning, ")")
          ),
          React.createElement("div", {className: "flex gap-3"},
            React.createElement("button", {
              onClick: () => setShowLibrary(true),
              className: "px-5 py-2.5 border-2 border-brand-primary-accent text-brand-primary-accent rounded-lg font-semibold hover:bg-brand-primary-accent hover:text-white transition-colors flex items-center gap-2 text-sm"
            },
              React.createElement(FileText, { className: "w-4 h-4" }),
              t.actions.viewLibrary
            ),
            React.createElement("button", {
              onClick: handleAnalyzeRequest,
              disabled: rawRequest.length < MIN_RAW_REQUEST_LENGTH,
              className: `px-5 py-2.5 rounded-lg font-semibold transition-all flex items-center gap-2 text-sm ${rawRequest.length < MIN_RAW_REQUEST_LENGTH ? 'bg-gray-300 text-gray-500 cursor-not-allowed' : 'bg-brand-primary-accent text-white hover:bg-opacity-80 cursor-pointer'}`
            },
              t.input.button,
              React.createElement(ChevronRight, { className: "w-4 h-4" })
            )
          )
        )
      ),
      step === 2 && React.createElement("div", { className: "space-y-6" },
        React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8" },
          React.createElement("h2", { className: "text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50" }, t.analysis.title),
          React.createElement("div", { className: "grid md:grid-cols-3 gap-4 text-center" },
            [
              { Icon: Brain, label: t.analysis.domain, value: t.domains[analyzedDomain], color: 'text-brand-primary-accent' },
              { Icon: Sparkles, label: t.analysis.complexity, value: analyzedComplexity === 'complex' ? t.analysis.complex : t.analysis.simple, color: 'text-brand-secondary-accent' },
              { Icon: AlertCircle, label: t.analysis.recommendation, value: recommendedType, color: 'text-brand-info' }
            ].map(item => React.createElement("div", { key: item.label, className: "p-4 bg-brand-bg/50 rounded-lg" },
              React.createElement(item.Icon, { className: `w-8 h-8 mx-auto mb-2 ${item.color}` }),
              React.createElement("p", { className: "font-semibold text-sm text-brand-text" }, item.label),
              React.createElement("p", { className: "text-lg text-brand-text" }, item.value)
            ))
          )
        ),
        React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8" },
          React.createElement("h2", { className: "text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50" }, t.approach.title),
          React.createElement("div", { className: "grid md:grid-cols-2 gap-4" },
            [
              { type: 'MVP', title: t.approach.mvp.title, subtitle: t.approach.mvp.subtitle, description: t.approach.mvp.description },
              { type: 'AGENTIC', title: t.approach.agentique.title, subtitle: t.approach.agentique.subtitle, description: t.approach.agentique.description }
            ].map(item => React.createElement("button", {
              key: item.type,
              onClick: () => setPromptType(item.type),
              className: `p-5 rounded-lg border-2 text-left transition-all ${promptType === item.type ? 'border-brand-primary-accent bg-brand-primary-accent/10 ring-2 ring-brand-primary-accent' : 'border-gray-300 hover:border-brand-primary-accent/70 hover:bg-brand-primary-accent/5'}`
            },
              React.createElement("h3", { className: "text-lg font-semibold text-brand-text mb-1" }, item.title),
              React.createElement("p", { className: "text-xs text-brand-muted-text mb-2" }, item.subtitle),
              React.createElement("p", { className: "text-sm text-brand-text" }, item.description)
            ))
          ),
          React.createElement("div", { className: "flex justify-between items-center mt-6" },
            React.createElement("button", {
              onClick: () => setStep(1),
              className: "px-5 py-2.5 border-2 border-gray-300 text-brand-muted-text rounded-lg font-semibold hover:bg-gray-100 hover:border-gray-400 transition-colors text-sm"
            }, t.variables.back),
            React.createElement("button", {
              onClick: () => setStep(3),
              className: "px-5 py-2.5 bg-brand-primary-accent text-white rounded-lg font-semibold hover:bg-opacity-80 transition-all flex items-center gap-2 text-sm"
            },
              t.variables.next,
              React.createElement(ChevronRight, { className: "w-4 h-4" })
            )
          )
        )
      ),
      step === 3 && React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8" },
        React.createElement("h2", { className: "text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50" }, t.variables.title),
        React.createElement("div", { className: "space-y-5" },
          [
            { label: t.variables.domain, value: selectedDomain, onChange: (e) => setSelectedDomain(e.target.value), options: DOMAIN_OPTIONS.map(opt => ({ value: opt.value, label: t.domains[opt.labelToken] })) },
            { label: t.variables.outputLength, value: outputLength, onChange: (e) => setOutputLength(e.target.value), options: OUTPUT_LENGTH_OPTIONS.map(opt => ({ value: opt.value, label: t.lengths[opt.labelToken] })) }
          ].map(item => React.createElement("div", { key: item.label },
            React.createElement("label", { className: "block text-sm font-medium text-brand-text mb-1.5" }, item.label),
            React.createElement("select", { value: item.value, onChange: item.onChange, className: "w-full p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none text-base" },
              item.options.map(opt => React.createElement("option", { key: opt.value, value: opt.value }, opt.label))
            )
          )),
          [
            { label: t.variables.expertRole, value: expertRole, onChange: (e) => setExpertRole(e.target.value), placeholder: t.variables.expertRolePlaceholder, type: 'input' },
            { label: t.variables.mission, value: mission, onChange: (e) => setMission(e.target.value), placeholder: t.variables.missionPlaceholder, type: 'input' },
            { label: t.variables.constraints, value: constraints, onChange: (e) => setConstraints(e.target.value), placeholder: t.variables.constraintsPlaceholder, type: 'textarea' }
          ].map(item => React.createElement("div", { key: item.label },
            React.createElement("label", { className: "block text-sm font-medium text-brand-text mb-1.5" }, item.label),
            item.type === 'input' ? React.createElement("input", { type: "text", value: item.value, onChange: item.onChange, placeholder: item.placeholder, className: "w-full p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none text-base" })
                                  : React.createElement("textarea", { value: item.value, onChange: item.onChange, placeholder: item.placeholder, className: "w-full h-32 p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none resize-none text-base" })
          ))
        ),
        React.createElement("div", { className: "flex justify-between items-center mt-6" },
          React.createElement("button", { onClick: () => setStep(2), className: "px-5 py-2.5 border-2 border-gray-300 text-brand-muted-text rounded-lg font-semibold hover:bg-gray-100 hover:border-gray-400 transition-colors text-sm" }, t.variables.back),
          React.createElement("button", { onClick: handleGeneratePrompt, className: "px-5 py-2.5 bg-brand-primary-accent text-white rounded-lg font-semibold hover:bg-opacity-80 transition-all flex items-center gap-2 text-sm" },
            t.actions.generate, React.createElement(ChevronRight, { className: "w-4 h-4" })
          )
        )
      ),
      step === 4 && React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8" },
        React.createElement("h2", { className: "text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50" }, t.generation.title),
        isGenerating ? React.createElement("div", { className: "text-center py-12" },
          React.createElement(Loader2, { className: "w-12 h-12 mx-auto animate-spin text-brand-primary-accent mb-4" }),
          React.createElement("p", { className: "text-brand-muted-text text-lg" }, t.generation.generating)
        ) : React.createElement(React.Fragment, null,
          React.createElement("div", { className: "bg-brand-bg/50 rounded-lg border-l-4 border-brand-primary-accent p-4 font-courier text-sm text-brand-text whitespace-pre-wrap max-h-[500px] overflow-y-auto shadow-inner" },
            generatedPrompt || "No prompt generated yet."
          ),
          React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6" },
            React.createElement("button", { onClick: copyToClipboard, className: "w-full px-4 py-2.5 bg-brand-primary-accent text-white rounded-lg font-semibold hover:bg-opacity-80 transition-all flex items-center justify-center gap-2 text-sm" }, React.createElement(Copy, { className: "w-4 h-4" }), t.actions.copy),
            React.createElement("button", { onClick: savePrompt, className: "w-full px-4 py-2.5 border-2 border-brand-primary-accent text-brand-primary-accent rounded-lg font-semibold hover:bg-brand-primary-accent hover:text-white transition-colors flex items-center justify-center gap-2 text-sm" }, React.createElement(Save, { className: "w-4 h-4" }), t.actions.save),
            React.createElement("button", { onClick: exportPrompt, className: "w-full px-4 py-2.5 border-2 border-brand-primary-accent text-brand-primary-accent rounded-lg font-semibold hover:bg-brand-primary-accent hover:text-white transition-colors flex items-center justify-center gap-2 text-sm" }, React.createElement(Download, { className: "w-4 h-4" }), t.actions.export)
          ),
          React.createElement("button", { onClick: resetForm, className: "w-full mt-4 px-5 py-3 bg-brand-secondary-accent text-brand-text rounded-lg font-semibold hover:bg-opacity-80 transition-all text-base" }, t.actions.newPrompt)
        )
      ),
      showLibrary && React.createElement("div", { className: "fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50 backdrop-blur-sm" },
        React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand-lg max-w-2xl w-full max-h-[85vh] flex flex-col" },
          React.createElement("div", { className: "p-5 border-b border-gray-200 flex justify-between items-center" },
            React.createElement("h2", { className: "text-xl font-semibold text-brand-text" }, t.library.title),
            React.createElement("button", { onClick: () => setShowLibrary(false), className: "p-2 hover:bg-gray-100 rounded-full text-brand-muted-text hover:text-brand-text" }, React.createElement(X, { className: "w-5 h-5" }))
          ),
          React.createElement("div", { className: "p-5 overflow-y-auto flex-grow" },
            savedPrompts.length === 0 ? React.createElement("p", { className: "text-center text-brand-muted-text py-10" }, t.library.empty)
            : React.createElement("div", { className: "space-y-3" },
              savedPrompts.map((prompt) => React.createElement("div", { key: prompt.id, className: "border border-gray-200 rounded-lg p-4 hover:bg-brand-bg/50 transition-colors" },
                React.createElement("div", { className: "flex justify-between items-start mb-1.5" },
                  React.createElement("p", { className: "font-semibold text-brand-text text-sm break-all mr-2" }, prompt.rawRequest.substring(0, 70), prompt.rawRequest.length > 70 ? '...' : ''),
                  React.createElement("div", { className: "flex-shrink-0 flex items-center gap-2" },
                     React.createElement("button", { 
                        onClick: () => loadPromptFromLibrary(prompt), 
                        className: "px-3 py-1.5 bg-brand-primary-accent text-white rounded-md text-xs hover:bg-opacity-80 whitespace-nowrap flex items-center gap-1",
                        title: t.actions.usePrompt
                      }, 
                      React.createElement(FileText, {className: "w-3 h-3"}),
                      t.actions.usePrompt
                    ),
                    React.createElement("button", { 
                        onClick: () => handleDeletePrompt(prompt.id), 
                        className: "px-3 py-1.5 bg-brand-error/10 text-brand-error rounded-md text-xs hover:bg-brand-error hover:text-white whitespace-nowrap flex items-center gap-1",
                        title: t.actions.delete
                      }, 
                      React.createElement(Trash2, {className: "w-3 h-3"}),
                      t.actions.delete
                    )
                  )
                ),
                React.createElement("p", { className: "text-xs text-brand-muted-text" },
                  new Date(prompt.timestamp).toLocaleDateString(language), " • ", prompt.type, " • ", t.domains[prompt.domain]
                )
              ))
            )
          )
        )
      ),
      notification && React.createElement("div", { className: "fixed bottom-6 right-6 bg-brand-text text-white px-5 py-3 rounded-lg shadow-brand-lg flex items-center gap-3 z-[100]" },
        React.createElement(Check, { className: "w-5 h-5 text-brand-success" }), // Consider changing icon based on notification type
        React.createElement("span", null, notification)
      )
    )
  );
}

export default App;
