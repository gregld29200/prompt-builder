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
      placeholder: "Exemple: Transformer cet article de presse en activités de compréhension écrite adaptées à des étudiants A2, avec focus sur le passé composé...",
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
      delete: "Supprimer",
      backToDashboard: "Tableau de bord",
      backToDashboardFull: "Retour tableau de bord"
    },
    library: {
      title: "Bibliothèque de prompts",
      empty: "Aucun prompt sauvegardé",
      close: "Fermer",
      searchPlaceholder: "Rechercher dans mes prompts...",
      promptsAvailable: "disponible",
      promptsAvailablePlural: "disponibles",
      noResultsFound: "Aucun résultat trouvé",
      noResultsMessage: "Aucun prompt ne correspond à",
      tryOtherSearch: "Essayez un autre terme de recherche.",
      emptyMessage: "Vous n'avez pas encore sauvegardé de prompts. Commencez par créer votre premier prompt !"
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
      deleted: "Prompt supprimé !",
      saveError: "Échec de la sauvegarde du prompt.",
      deleteError: "Échec de la suppression du prompt."
    },
    auth: {
      loading: "Chargement...",
      login: {
        title: "Connexion",
        subtitle: "Connectez-vous à votre compte Teachinspire",
        signIn: "Se connecter",
        signingIn: "Connexion...",
        noAccount: "Pas encore de compte ?",
        signUpLink: "Créer un compte"
      },
      register: {
        title: "Créer un compte",
        subtitle: "Rejoignez Teachinspire pour sauvegarder vos prompts",
        createAccount: "Créer le compte",
        creatingAccount: "Création...",
        hasAccount: "Déjà un compte ?",
        signInLink: "Se connecter",
        passwordRequirements: "Exigences du mot de passe :",
        requirements: {
          length: "Au moins 8 caractères",
          lowercase: "Une lettre minuscule",
          uppercase: "Une lettre majuscule",
          number: "Un chiffre",
          special: "Un caractère spécial"
        }
      },
      fields: {
        email: "Adresse e-mail",
        password: "Mot de passe",
        confirmPassword: "Confirmer le mot de passe"
      },
      placeholders: {
        email: "votre@email.com",
        password: "Votre mot de passe",
        confirmPassword: "Confirmez votre mot de passe"
      },
      validation: {
        emailRequired: "L'adresse e-mail est requise",
        emailInvalid: "Adresse e-mail invalide",
        passwordRequired: "Le mot de passe est requis",
        passwordMinLength: "Minimum 6 caractères",
        passwordMinLength8: "Minimum 8 caractères",
        confirmPasswordRequired: "Veuillez confirmer votre mot de passe",
        passwordsDoNotMatch: "Les mots de passe ne correspondent pas"
      },
      errors: {
        loginFailed: "Échec de la connexion. Vérifiez vos identifiants.",
        registrationFailed: "Échec de l'inscription. Veuillez réessayer.",
        networkError: "Erreur réseau. Vérifiez votre connexion.",
        serverError: "Erreur serveur. Veuillez réessayer plus tard."
      },
      user: {
        unknown: "Utilisateur",
        signedInAs: "Connecté en tant que",
        settings: "Paramètres",
        signOut: "Se déconnecter"
      },
      migration: {
        title: "Migration des prompts",
        description: "Nous transférons vos prompts sauvegardés vers votre compte...",
        progress: "Migration en cours: {completed}/{total} prompts",
        success: "Migration réussie! {migrated} prompts transférés",
        successWithErrors: "Migration terminée avec {migrated} prompts transférés et {failed} échecs",
        failed: "Échec de la migration. Veuillez réessayer.",
        retry: "Réessayer la migration",
        skip: "Ignorer pour l'instant",
        detecting: "Détection des prompts à migrer...",
        backup: "Sauvegarde des données en cours...",
        uploading: "Envoi des prompts...",
        finalizing: "Finalisation...",
        noPromptsFound: "Aucun prompt à migrer trouvé",
        partialSuccess: "Migration partiellement réussie",
        errors: {
          networkError: "Erreur réseau lors de la migration",
          validationError: "Erreur de validation des données",
          serverError: "Erreur serveur lors de la migration",
          backupFailed: "Échec de la sauvegarde des données",
          unknown: "Erreur inconnue lors de la migration"
        }
      }
    }
  },
  en: {
    app: {
      title: "Teachinspire Prompt Builder",
      subtitle: "Transform your ideas into structured, effective prompts"
    },
    input: {
      placeholder: "Example: Transform this news article into reading comprehension activities adapted for A2 students, with focus on past tense...",
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
      delete: "Delete",
      backToDashboard: "Dashboard",
      backToDashboardFull: "Back to Dashboard"
    },
    library: {
      title: "Prompt Library",
      empty: "No saved prompts",
      close: "Close",
      searchPlaceholder: "Search in my prompts...",
      promptsAvailable: "available",
      promptsAvailablePlural: "available",
      noResultsFound: "No results found",
      noResultsMessage: "No prompts match",
      tryOtherSearch: "Try a different search term.",
      emptyMessage: "You haven't saved any prompts yet. Start by creating your first prompt!"
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
      deleted: "Prompt deleted!",
      saveError: "Failed to save prompt.",
      deleteError: "Failed to delete prompt."
    },
    auth: {
      loading: "Loading...",
      login: {
        title: "Sign In",
        subtitle: "Sign in to your Teachinspire account",
        signIn: "Sign In",
        signingIn: "Signing in...",
        noAccount: "Don't have an account?",
        signUpLink: "Create account"
      },
      register: {
        title: "Create Account",
        subtitle: "Join Teachinspire to save your prompts",
        createAccount: "Create Account",
        creatingAccount: "Creating...",
        hasAccount: "Already have an account?",
        signInLink: "Sign in",
        passwordRequirements: "Password requirements:",
        requirements: {
          length: "At least 8 characters",
          lowercase: "One lowercase letter",
          uppercase: "One uppercase letter",
          number: "One number",
          special: "One special character"
        }
      },
      fields: {
        email: "Email Address",
        password: "Password",
        confirmPassword: "Confirm Password"
      },
      placeholders: {
        email: "your@email.com",
        password: "Your password",
        confirmPassword: "Confirm your password"
      },
      validation: {
        emailRequired: "Email address is required",
        emailInvalid: "Invalid email address",
        passwordRequired: "Password is required",
        passwordMinLength: "Minimum 6 characters",
        passwordMinLength8: "Minimum 8 characters",
        confirmPasswordRequired: "Please confirm your password",
        passwordsDoNotMatch: "Passwords do not match"
      },
      errors: {
        loginFailed: "Login failed. Check your credentials.",
        registrationFailed: "Registration failed. Please try again.",
        networkError: "Network error. Check your connection.",
        serverError: "Server error. Please try again later."
      },
      user: {
        unknown: "User",
        signedInAs: "Signed in as",
        settings: "Settings",
        signOut: "Sign Out"
      },
      migration: {
        title: "Prompt Migration",
        description: "We're transferring your saved prompts to your account...",
        progress: "Migration in progress: {completed}/{total} prompts",
        success: "Migration successful! {migrated} prompts transferred",
        successWithErrors: "Migration completed with {migrated} prompts transferred and {failed} failures",
        failed: "Migration failed. Please try again.",
        retry: "Retry Migration",
        skip: "Skip for now",
        detecting: "Detecting prompts to migrate...",
        backup: "Backing up data...",
        uploading: "Uploading prompts...",
        finalizing: "Finalizing...",
        noPromptsFound: "No prompts found to migrate",
        partialSuccess: "Migration partially successful",
        errors: {
          networkError: "Network error during migration",
          validationError: "Data validation error",
          serverError: "Server error during migration",
          backupFailed: "Failed to backup data",
          unknown: "Unknown error during migration"
        }
      }
    }
  }
};
