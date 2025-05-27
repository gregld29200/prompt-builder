
import React, { useState, useEffect, useCallback } from 'react';
import { ChevronRight, Copy, Save, Download, Languages, Sparkles, Brain, Check, X, AlertCircle, FileText, Clock, Star, Loader2 } from 'lucide-react';
import type { PromptType, Language, Domain, Complexity, OutputLength, SavedPrompt, Translations } from './types';
import { translations, DEFAULT_LANGUAGE, MIN_RAW_REQUEST_LENGTH, MAX_RAW_REQUEST_LENGTH, DOMAIN_OPTIONS, OUTPUT_LENGTH_OPTIONS } from './constants';
import { generateStructuredPromptWithGemini } from './services/geminiService';

const App: React.FC = () => {
  const [language, setLanguage] = useState<Language>(DEFAULT_LANGUAGE);
  const [step, setStep] = useState(1);
  const [rawRequest, setRawRequest] = useState('');
  const [promptType, setPromptType] = useState<PromptType>('MVP');
  
  // Analysis results
  const [analyzedDomain, setAnalyzedDomain] = useState<Domain>('other');
  const [analyzedComplexity, setAnalyzedComplexity] = useState<Complexity>('simple');
  const [recommendedType, setRecommendedType] = useState<PromptType>('MVP');

  // User-configurable variables
  const [selectedDomain, setSelectedDomain] = useState<Domain>('education');
  const [outputLength, setOutputLength] = useState<OutputLength>('medium');
  const [expertRole, setExpertRole] = useState('');
  const [mission, setMission] = useState('');
  const [constraints, setConstraints] = useState('');
  
  const [generatedPrompt, setGeneratedPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [showLibrary, setShowLibrary] = useState(false);
  const [savedPrompts, setSavedPrompts] = useState<SavedPrompt[]>([]);
  const [notification, setNotification] = useState('');
  
  const t = translations[language];

  useEffect(() => {
    const saved = localStorage.getItem('teachinspire-prompts');
    if (saved) {
      try {
        setSavedPrompts(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to parse saved prompts from localStorage", e);
        localStorage.removeItem('teachinspire-prompts'); // Clear corrupted data
      }
    }
  }, []);

  const analyzeUserRequest = useCallback((request: string): { domain: Domain; complexity: Complexity; recommendedType: PromptType } => {
    const educationKeywords = ['cours', 'leçon', 'lesson', 'élève', 'student', 'apprendre', 'learn', 'enseigner', 'teach', 'pédagogie', 'pedagogy'];
    const technicalKeywords = ['code', 'algorithm', 'database', 'api', 'système', 'system', 'technique', 'software', 'hardware', 'network'];
    const creativeKeywords = ['story', 'histoire', 'créer', 'create', 'design', 'art', 'écrire', 'write', 'roman', 'poème', 'scénario'];
    const analysisKeywords = ['analyser', 'analyze', 'rapport', 'report', 'données', 'data', 'évaluer', 'evaluate', 'recherche', 'research'];
    
    const requestLower = request.toLowerCase();
    
    let detectedDomain: Domain = 'other';
    if (educationKeywords.some(k => requestLower.includes(k))) detectedDomain = 'education';
    else if (technicalKeywords.some(k => requestLower.includes(k))) detectedDomain = 'technical';
    else if (creativeKeywords.some(k => requestLower.includes(k))) detectedDomain = 'creative';
    else if (analysisKeywords.some(k => requestLower.includes(k))) detectedDomain = 'analysis';
    
    const complexIndicators = ['plusieurs', 'multiple', 'complexe', 'complex', 'détaillé', 'detailed', 'approfondi', 'comprehensive', 'stratégie', 'strategy'];
    const isComplex = complexIndicators.some(k => requestLower.includes(k)) || request.length > 250; // Adjusted length threshold
    
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
      // Pre-fill form based on analysis
      setSelectedDomain(analysis.domain); 
      setPromptType(analysis.recommendedType);
      setStep(2);
    }
  };
  
  const handleGeneratePrompt = async () => {
    setIsGenerating(true);
    setStep(4); // Move to step 4 to show generating state

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

  const showNotification = (message: string, type: 'success' | 'error' = 'success') => {
    setNotification(message);
    // Add logic for different notification types if styling changes based on type
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
    const newPromptData: SavedPrompt = {
      id: Date.now().toString(),
      timestamp: Date.now(),
      rawRequest,
      generatedPrompt,
      type: promptType,
      domain: selectedDomain,
      language
    };
    
    const updatedPrompts = [newPromptData, ...savedPrompts]; // Add to beginning
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
    // Reset analysis too
    setAnalyzedDomain('other');
    setAnalyzedComplexity('simple');
    setRecommendedType('MVP');
    // Reset configurable options to defaults
    setSelectedDomain('education');
    setOutputLength('medium');
    setPromptType('MVP');
  };

  const loadPromptFromLibrary = (promptData: SavedPrompt) => {
    setRawRequest(promptData.rawRequest);
    setGeneratedPrompt(promptData.generatedPrompt);
    setPromptType(promptData.type);
    setSelectedDomain(promptData.domain);
    // Potentially set other fields like expertRole, mission, constraints if they were saved
    // For now, just loading the core parts to view/use the generated prompt.
    // If we want to allow re-editing, more state needs to be restored.
    setLanguage(promptData.language); // Switch to language of saved prompt
    setShowLibrary(false);
    setStep(4); // Go directly to view the loaded prompt
    setIsGenerating(false); // Ensure not in generating state
  };


  return (
    <div className="min-h-screen bg-brand-bg text-brand-text font-inter">
      <header className="bg-brand-card-bg shadow-brand">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <img 
            src="https://res.cloudinary.com/ducvoebot/image/upload/v1747991665/Teachinspire_logo_transparent_yjt3uf.png"
            alt="Teachinspire Logo"
            className="h-12 md:h-16 w-auto" // Adjusted size slightly
          />
          <button
            onClick={() => setLanguage(language === 'fr' ? 'en' : 'fr')}
            className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-brand-primary-accent/10 text-brand-primary-accent transition-colors"
            aria-label={language === 'fr' ? 'Switch to English' : 'Passer au Français'}
          >
            <Languages className="w-5 h-5" />
            <span className="font-medium">{language.toUpperCase()}</span>
          </button>
        </div>
      </header>

      <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-8 max-w-3xl"> {/* Adjusted max-width */}
        <div className="text-center mb-10">
          <h1 className="font-playfair text-3xl md:text-4xl font-bold text-brand-text mb-3">
            {t.app.title}
          </h1>
          <p className="text-brand-primary-accent text-lg">{t.app.subtitle}</p>
        </div>

        {/* Step 1: Input */}
        {step === 1 && (
          <div className="bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8">
            <label htmlFor="rawRequestInput" className="block text-xl font-semibold text-brand-text mb-4 pb-2 border-b-2 border-brand-primary-accent/50">
              {t.input.placeholder}
            </label>
            <textarea
              id="rawRequestInput"
              value={rawRequest}
              onChange={(e) => setRawRequest(e.target.value)}
              placeholder={language === 'fr' 
                ? "Exemple: Je veux créer un cours interactif sur les énergies renouvelables pour des lycéens..."
                : "Example: I want to create an interactive lesson about renewable energy for high school students..."
              }
              className="w-full h-40 p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none resize-none font-inter text-base"
              maxLength={MAX_RAW_REQUEST_LENGTH}
            />
            <div className="flex flex-col sm:flex-row justify-between items-center mt-4 space-y-3 sm:space-y-0">
              <span className={`text-sm ${rawRequest.length < MIN_RAW_REQUEST_LENGTH && rawRequest.length > 0 ? 'text-brand-error' : 'text-brand-muted-text'}`}>
                {rawRequest.length}/{MAX_RAW_REQUEST_LENGTH} {t.input.charCount}
                {rawRequest.length > 0 && rawRequest.length < MIN_RAW_REQUEST_LENGTH && (
                  <span className="ml-2">({t.input.minCharWarning})</span>
                )}
              </span>
              <div className="flex gap-3">
                <button
                  onClick={() => setShowLibrary(true)}
                  className="px-5 py-2.5 border-2 border-brand-primary-accent text-brand-primary-accent rounded-lg font-semibold hover:bg-brand-primary-accent hover:text-white transition-colors flex items-center gap-2 text-sm"
                >
                  <FileText className="w-4 h-4" />
                  {t.actions.viewLibrary}
                </button>
                <button
                  onClick={handleAnalyzeRequest}
                  disabled={rawRequest.length < MIN_RAW_REQUEST_LENGTH}
                  className={`px-5 py-2.5 rounded-lg font-semibold transition-all flex items-center gap-2 text-sm ${
                    rawRequest.length < MIN_RAW_REQUEST_LENGTH 
                      ? 'bg-gray-300 text-gray-500 cursor-not-allowed' 
                      : 'bg-brand-primary-accent text-white hover:bg-opacity-80 cursor-pointer'
                  }`}
                >
                  {t.input.button}
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Step 2: Analysis & Approach Selection */}
        {step === 2 && (
          <div className="space-y-6">
            <div className="bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8">
              <h2 className="text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50">
                {t.analysis.title}
              </h2>
              <div className="grid md:grid-cols-3 gap-4 text-center">
                {[
                  { Icon: Brain, label: t.analysis.domain, value: t.domains[analyzedDomain], color: 'text-brand-primary-accent' },
                  { Icon: Sparkles, label: t.analysis.complexity, value: analyzedComplexity === 'complex' ? t.analysis.complex : t.analysis.simple, color: 'text-brand-secondary-accent' },
                  { Icon: AlertCircle, label: t.analysis.recommendation, value: recommendedType, color: 'text-brand-info' }
                ].map(item => (
                  <div key={item.label} className="p-4 bg-brand-bg/50 rounded-lg">
                    <item.Icon className={`w-8 h-8 mx-auto mb-2 ${item.color}`} />
                    <p className="font-semibold text-sm text-brand-text">{item.label}</p>
                    <p className="text-lg text-brand-text">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8">
              <h2 className="text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50">
                {t.approach.title}
              </h2>
              <div className="grid md:grid-cols-2 gap-4">
                {[
                  { type: 'MVP' as PromptType, title: t.approach.mvp.title, subtitle: t.approach.mvp.subtitle, description: t.approach.mvp.description },
                  { type: 'AGENTIC' as PromptType, title: t.approach.agentique.title, subtitle: t.approach.agentique.subtitle, description: t.approach.agentique.description }
                ].map(item => (
                  <button
                    key={item.type}
                    onClick={() => setPromptType(item.type)}
                    className={`p-5 rounded-lg border-2 text-left transition-all ${
                      promptType === item.type
                        ? 'border-brand-primary-accent bg-brand-primary-accent/10 ring-2 ring-brand-primary-accent'
                        : 'border-gray-300 hover:border-brand-primary-accent/70 hover:bg-brand-primary-accent/5'
                    }`}
                  >
                    <h3 className="text-lg font-semibold text-brand-text mb-1">{item.title}</h3>
                    <p className="text-xs text-brand-muted-text mb-2">{item.subtitle}</p>
                    <p className="text-sm text-brand-text">{item.description}</p>
                  </button>
                ))}
              </div>
              <div className="flex justify-between items-center mt-6">
                <button
                  onClick={() => setStep(1)}
                  className="px-5 py-2.5 border-2 border-gray-300 text-brand-muted-text rounded-lg font-semibold hover:bg-gray-100 hover:border-gray-400 transition-colors text-sm"
                >
                  {t.variables.back}
                </button>
                <button
                  onClick={() => setStep(3)}
                  className="px-5 py-2.5 bg-brand-primary-accent text-white rounded-lg font-semibold hover:bg-opacity-80 transition-all flex items-center gap-2 text-sm"
                >
                  {t.variables.next}
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}
        
        {/* Step 3: Variable Extraction */}
        {step === 3 && (
          <div className="bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8">
            <h2 className="text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50">
              {t.variables.title}
            </h2>
            <div className="space-y-5">
              {[
                { label: t.variables.domain, value: selectedDomain, onChange: (e: React.ChangeEvent<HTMLSelectElement>) => setSelectedDomain(e.target.value as Domain), options: DOMAIN_OPTIONS.map(opt => ({ value: opt.value, label: t.domains[opt.labelToken] })) },
                { label: t.variables.outputLength, value: outputLength, onChange: (e: React.ChangeEvent<HTMLSelectElement>) => setOutputLength(e.target.value as OutputLength), options: OUTPUT_LENGTH_OPTIONS.map(opt => ({ value: opt.value, label: t.lengths[opt.labelToken] })) }
              ].map(item => (
                <div key={item.label}>
                  <label className="block text-sm font-medium text-brand-text mb-1.5">{item.label}</label>
                  <select value={item.value} onChange={item.onChange} className="w-full p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none text-base">
                    {item.options.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                  </select>
                </div>
              ))}
              {[
                { label: t.variables.expertRole, value: expertRole, onChange: (e: React.ChangeEvent<HTMLInputElement>) => setExpertRole(e.target.value), placeholder: t.variables.expertRolePlaceholder, type: 'input' },
                { label: t.variables.mission, value: mission, onChange: (e: React.ChangeEvent<HTMLInputElement>) => setMission(e.target.value), placeholder: t.variables.missionPlaceholder, type: 'input' },
                { label: t.variables.constraints, value: constraints, onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => setConstraints(e.target.value), placeholder: t.variables.constraintsPlaceholder, type: 'textarea' }
              ].map(item => (
                <div key={item.label}>
                  <label className="block text-sm font-medium text-brand-text mb-1.5">{item.label}</label>
                  {item.type === 'input' ? (
                    <input type="text" value={item.value} onChange={item.onChange as (e: React.ChangeEvent<HTMLInputElement>) => void} placeholder={item.placeholder} className="w-full p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none text-base" />
                  ) : (
                    <textarea value={item.value} onChange={item.onChange as (e: React.ChangeEvent<HTMLTextAreaElement>) => void} placeholder={item.placeholder} className="w-full h-32 p-3 border-2 border-gray-300 rounded-lg focus:border-brand-primary-accent focus:ring-1 focus:ring-brand-primary-accent outline-none resize-none text-base" />
                  )}
                </div>
              ))}
            </div>
            <div className="flex justify-between items-center mt-6">
              <button onClick={() => setStep(2)} className="px-5 py-2.5 border-2 border-gray-300 text-brand-muted-text rounded-lg font-semibold hover:bg-gray-100 hover:border-gray-400 transition-colors text-sm">{t.variables.back}</button>
              <button onClick={handleGeneratePrompt} className="px-5 py-2.5 bg-brand-primary-accent text-white rounded-lg font-semibold hover:bg-opacity-80 transition-all flex items-center gap-2 text-sm">
                {t.actions.generate} <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Generated Prompt */}
        {step === 4 && (
          <div className="bg-brand-card-bg rounded-lg shadow-brand p-6 md:p-8">
            <h2 className="text-xl font-semibold text-brand-text mb-5 pb-2 border-b-2 border-brand-primary-accent/50">
              {t.generation.title}
            </h2>
            {isGenerating ? (
              <div className="text-center py-12">
                <Loader2 className="w-12 h-12 mx-auto animate-spin text-brand-primary-accent mb-4" />
                <p className="text-brand-muted-text text-lg">{t.generation.generating}</p>
              </div>
            ) : (
              <>
                <div className="bg-brand-bg/50 rounded-lg border-l-4 border-brand-primary-accent p-4 font-courier text-sm text-brand-text whitespace-pre-wrap max-h-[500px] overflow-y-auto shadow-inner">
                  {generatedPrompt || "No prompt generated yet."}
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6">
                  <button onClick={copyToClipboard} className="w-full px-4 py-2.5 bg-brand-primary-accent text-white rounded-lg font-semibold hover:bg-opacity-80 transition-all flex items-center justify-center gap-2 text-sm"><Copy className="w-4 h-4" />{t.actions.copy}</button>
                  <button onClick={savePrompt} className="w-full px-4 py-2.5 border-2 border-brand-primary-accent text-brand-primary-accent rounded-lg font-semibold hover:bg-brand-primary-accent hover:text-white transition-colors flex items-center justify-center gap-2 text-sm"><Save className="w-4 h-4" />{t.actions.save}</button>
                  <button onClick={exportPrompt} className="w-full px-4 py-2.5 border-2 border-brand-primary-accent text-brand-primary-accent rounded-lg font-semibold hover:bg-brand-primary-accent hover:text-white transition-colors flex items-center justify-center gap-2 text-sm"><Download className="w-4 h-4" />{t.actions.export}</button>
                </div>
                <button onClick={resetForm} className="w-full mt-4 px-5 py-3 bg-brand-secondary-accent text-brand-text rounded-lg font-semibold hover:bg-opacity-80 transition-all text-base">{t.actions.newPrompt}</button>
              </>
            )}
          </div>
        )}
      </main>

      {/* Library Modal */}
      {showLibrary && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-brand-card-bg rounded-lg shadow-brand-lg max-w-2xl w-full max-h-[85vh] flex flex-col">
            <div className="p-5 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-xl font-semibold text-brand-text">{t.library.title}</h2>
              <button onClick={() => setShowLibrary(false)} className="p-2 hover:bg-gray-100 rounded-full text-brand-muted-text hover:text-brand-text"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-5 overflow-y-auto flex-grow">
              {savedPrompts.length === 0 ? (
                <p className="text-center text-brand-muted-text py-10">{t.library.empty}</p>
              ) : (
                <div className="space-y-3">
                  {savedPrompts.map((prompt) => (
                    <div key={prompt.id} className="border border-gray-200 rounded-lg p-4 hover:bg-brand-bg/50 transition-colors">
                      <div className="flex justify-between items-start mb-1.5">
                        <p className="font-semibold text-brand-text text-sm break-all">{prompt.rawRequest.substring(0, 70)}{prompt.rawRequest.length > 70 ? '...' : ''}</p>
                        <button onClick={() => loadPromptFromLibrary(prompt)} className="ml-3 px-3 py-1.5 bg-brand-primary-accent text-white rounded-md text-xs hover:bg-opacity-80 whitespace-nowrap">{t.actions.usePrompt}</button>
                      </div>
                      <p className="text-xs text-brand-muted-text">
                        {new Date(prompt.timestamp).toLocaleDateString(language)} • {prompt.type} • {t.domains[prompt.domain]}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Notification Toast */}
      {notification && (
        <div className="fixed bottom-6 right-6 bg-brand-text text-white px-5 py-3 rounded-lg shadow-brand-lg flex items-center gap-3 z-[100]">
          <Check className="w-5 h-5 text-brand-success" /> {/* Use success/error icon based on type if implemented */}
          <span>{notification}</span>
        </div>
      )}
    </div>
  );
}

export default App;
