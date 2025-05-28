// import type { Language, Domain, OutputLength, Translations } from './types'; // TS types removed

export const DEFAULT_LANGUAGE = 'fr';
export const MIN_RAW_REQUEST_LENGTH = 10;
export const MAX_RAW_REQUEST_LENGTH = 2000;

export const DOMAIN_OPTIONS = [
  { value: 'education', labelToken: 'education' },
  { value: 'technical', labelToken: 'technical' },
  { value: 'creative', labelToken: 'creative' },
  { value: 'analysis', labelToken: 'analysis' },
  { value: 'other', labelToken: 'other' },
];

export const OUTPUT_LENGTH_OPTIONS = [
  { value: 'short', labelToken: 'short' },
  { value: 'medium', labelToken: 'medium' },
  { value: 'long', labelToken: 'long' },
];

export const translations = {
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
      expertRoleDescription: "Préciser le rôle que vous voulez donner à l'IA pour cette tâche - sa fonction.",
      expertRolePlaceholder: "Ex: Concepteur pédagogique",
      mission: "Mission principale",
      missionDescription: "Préciser les tâches que vous voulez que l'IA exécute - sa mission.",
      missionPlaceholder: "Ex: créer des cours engageants",
      constraints: "Contraintes (une par ligne)",
      next: "Suivant",
      back: "Retour",
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
      usePrompt: "Utiliser",
      delete: "Supprimer"
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
      apiError: "Erreur de l'API Gemini. Veuillez vérifier votre clé API et réessayer.",
      deleted: "Prompt supprimé !"
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
      expertRoleDescription: "Specify the role you want the AI to play for this task - its function.",
      expertRolePlaceholder: "Ex: Instructional Designer",
      mission: "Main mission",
      missionDescription: "Specify the tasks you want the AI to perform - its mission.",
      missionPlaceholder: "Ex: create engaging courses",
      constraints: "Constraints (one per line)",
      next: "Next",
      back: "Back",
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
      usePrompt: "Use",
      delete: "Delete"
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
      apiError: "Gemini API error. Please check your API key and try again.",
      deleted: "Prompt deleted!"
    }
  }
};
