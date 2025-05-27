
import type { Language, Domain, OutputLength, Translations } from './types';

export const DEFAULT_LANGUAGE: Language = 'fr';
export const MIN_RAW_REQUEST_LENGTH = 10;
export const MAX_RAW_REQUEST_LENGTH = 2000;

export const DOMAIN_OPTIONS: { value: Domain; labelToken: keyof Translations['en']['domains'] }[] = [
  { value: 'education', labelToken: 'education' },
  { value: 'technical', labelToken: 'technical' },
  { value: 'creative', labelToken: 'creative' },
  { value: 'analysis', labelToken: 'analysis' },
  { value: 'other', labelToken: 'other' },
];

export const OUTPUT_LENGTH_OPTIONS: { value: OutputLength; labelToken: keyof Translations['en']['lengths'] }[] = [
  { value: 'short', labelToken: 'short' },
  { value: 'medium', labelToken: 'medium' },
  { value: 'long', labelToken: 'long' },
];

export const translations: Translations = {
  fr: {
    app: {
      title: "Prompt Builder Teachinspire",
      subtitle: "Transformez vos idées en prompts structurés efficaces"
    },
    input: {
      placeholder: "Décrivez ce que vous voulez faire avec l'IA...",
      button: "Analyser ma demande",
      charCount: "caractères",
      minCharWarning: `Minimum ${MIN_RAW_REQUEST_LENGTH} caractères requis`
    },
    analysis: {
      title: "Analyse de votre demande",
      domain: "Domaine détecté",
      complexity: "Complexité estimée",
      recommendation: "Approche recommandée",
      simple: "Simple",
      complex: "Complexe"
    },
    approach: {
      title: "Choisissez votre approche",
      mvp: {
        title: "MVP",
        subtitle: "(Recommandé pour tâches simples)",
        description: "Structure simple System-User-Exemple"
      },
      agentique: {
        title: "AGENTIQUE",
        subtitle: "(Pour tâches complexes)",
        description: "Avec auto-évaluation et itération"
      }
    },
    variables: {
      title: "Affiner votre prompt",
      domain: "Domaine",
      outputLength: "Longueur de sortie",
      expertRole: "Rôle de l'expert",
      mission: "Mission principale",
      constraints: "Contraintes (une par ligne)",
      next: "Suivant",
      back: "Retour",
      expertRolePlaceholder: "Ex: Concepteur pédagogique",
      missionPlaceholder: "Ex: créer des cours engageants",
      constraintsPlaceholder: "Ex:\nDurée: 50 minutes\nNiveau: B1\nGroupe: 12 élèves"
    },
    generation: {
      generating: "Génération en cours...",
      title: "Votre prompt structuré",
      error: "Erreur de génération. Veuillez réessayer."
    },
    actions: {
      copy: "Copier",
      save: "Sauvegarder",
      export: "Exporter",
      generate: "Générer le prompt",
      newPrompt: "Nouveau prompt",
      viewLibrary: "Mes prompts",
      copiedSuccess: "Copié!",
      copyError: "Erreur de copie",
      savedSuccess: "Sauvegardé!",
      usePrompt: "Utiliser"
    },
    library: {
      title: "Bibliothèque de prompts",
      empty: "Aucun prompt sauvegardé",
      close: "Fermer"
    },
    domains: {
      education: "Éducation",
      technical: "Technique",
      creative: "Créatif",
      analysis: "Analyse",
      other: "Autre"
    },
    lengths: {
      short: "Court",
      medium: "Moyen",
      long: "Long"
    },
    notifications: {
      copied: "Prompt copié dans le presse-papiers!",
      copyFailed: "Échec de la copie du prompt.",
      saved: "Prompt sauvegardé dans la bibliothèque!",
      apiError: "Erreur de l'API Gemini. Veuillez vérifier votre clé API et réessayer."
    }
  },
  en: {
    app: {
      title: "Teachinspire Prompt Builder",
      subtitle: "Transform your ideas into structured, effective prompts"
    },
    input: {
      placeholder: "Describe what you want to do with AI...",
      button: "Analyze my request",
      charCount: "characters",
      minCharWarning: `Minimum ${MIN_RAW_REQUEST_LENGTH} characters required`
    },
    analysis: {
      title: "Analysis of your request",
      domain: "Detected domain",
      complexity: "Estimated complexity",
      recommendation: "Recommended approach",
      simple: "Simple",
      complex: "Complex"
    },
    approach: {
      title: "Choose your approach",
      mvp: {
        title: "MVP",
        subtitle: "(Recommended for simple tasks)",
        description: "Simple System-User-Example structure"
      },
      agentique: {
        title: "AGENTIC",
        subtitle: "(For complex tasks)",
        description: "With self-assessment and iteration"
      }
    },
    variables: {
      title: "Refine your prompt",
      domain: "Domain",
      outputLength: "Output length",
      expertRole: "Expert role",
      mission: "Main mission",
      constraints: "Constraints (one per line)",
      next: "Next",
      back: "Back",
      expertRolePlaceholder: "Ex: Instructional Designer",
      missionPlaceholder: "Ex: create engaging courses",
      constraintsPlaceholder: "Ex:\nDuration: 50 minutes\nLevel: B1\nGroup: 12 students"
    },
    generation: {
      generating: "Generating...",
      title: "Your structured prompt",
      error: "Generation error. Please try again."
    },
    actions: {
      copy: "Copy",
      save: "Save",
      export: "Export",
      generate: "Generate prompt",
      newPrompt: "New prompt",
      viewLibrary: "My prompts",
      copiedSuccess: "Copied!",
      copyError: "Copy failed",
      savedSuccess: "Saved!",
      usePrompt: "Use"
    },
    library: {
      title: "Prompt Library",
      empty: "No saved prompts",
      close: "Close"
    },
    domains: {
      education: "Education",
      technical: "Technical",
      creative: "Creative",
      analysis: "Analysis",
      other: "Other"
    },
    lengths: {
      short: "Short",
      medium: "Medium",
      long: "Long"
    },
    notifications: {
      copied: "Prompt copied to clipboard!",
      copyFailed: "Failed to copy prompt.",
      saved: "Prompt saved to library!",
      apiError: "Gemini API error. Please check your API key and try again."
    }
  }
};
