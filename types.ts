
export type PromptType = 'MVP' | 'AGENTIC';
export type Language = 'fr' | 'en';
export type Domain = 'education' | 'technical' | 'creative' | 'analysis' | 'other';
export type Complexity = 'auto' | 'simple' | 'complex'; // 'auto' might not be used if we always determine it
export type OutputLength = 'short' | 'medium' | 'long';

export interface SavedPrompt {
  id: string;
  timestamp: number;
  rawRequest: string;
  generatedPrompt: string;
  type: PromptType;
  domain: Domain;
  language: Language;
  favorite?: boolean; // Kept for potential future use
}

// For translations structure
interface TranslationSet {
  app: {
    title: string;
    subtitle: string;
  };
  input: {
    placeholder: string;
    button: string;
    charCount: string;
    minCharWarning: string;
  };
  analysis: {
    title: string;
    domain: string;
    complexity: string;
    recommendation: string;
    simple: string;
    complex: string;
  };
  approach: {
    title: string;
    mvp: {
      title: string;
      subtitle: string;
      description: string;
    };
    agentique: {
      title: string;
      subtitle: string;
      description: string;
    };
  };
  variables: {
    title: string;
    domain: string;
    outputLength: string;
    expertRole: string;
    mission: string;
    constraints: string;
    next: string;
    back: string;
    expertRolePlaceholder: string;
    missionPlaceholder: string;
    constraintsPlaceholder: string;
  };
  generation: {
    generating: string;
    title: string;
    error: string;
  };
  actions: {
    copy: string;
    save: string;
    export: string;
    generate: string;
    newPrompt: string;
    viewLibrary: string;
    copiedSuccess: string;
    copyError: string;
    savedSuccess: string;
    usePrompt: string;
  };
  library: {
    title: string;
    empty: string;
    close: string;
  };
  domains: {
    education: string;
    technical: string;
    creative: string;
    analysis: string;
    other: string;
  };
  lengths: {
    short: string;
    medium: string;
    long: string;
  };
  notifications: {
    copied: string;
    copyFailed: string;
    saved: string;
    apiError: string;
  }
}

export type Translations = {
  fr: TranslationSet;
  en: TranslationSet;
};
