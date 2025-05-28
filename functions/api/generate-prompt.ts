// File: functions/api/generate-prompt.ts

import { GoogleGenAI } from "@google/genai";
import type { Language, Domain, OutputLength, PromptType } from '../../types'; // Adjust path as needed
import { translations as appTranslations } from '../../constants'; // Renamed to avoid conflict

// This is the structure of the incoming request body from the client
interface GeneratePromptParams {
  rawRequest: string;
  promptType: PromptType;
  domain: Domain;
  language: Language;
  outputLength: OutputLength;
  expertRole: string;
  mission: string;
  constraints: string;
}

// Define the structure for Cloudflare Pages Functions onRequestPost
// The 'context' object contains 'request' and 'env'
interface EventContext {
  request: Request;
  env: {
    API_KEY?: string; // Environment variable for the API key
    [key: string]: any; // Allows for other environment variables
  };
  params: any; // For route parameters, not used here
  waitUntil: (promise: Promise<any>) => void;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  functionPath: string;
}

// Enhanced metaPromptTranslations with detailed methodology for both approaches
const metaPromptTranslations = {
  en: {
    systemInstructionBase: "You are an expert prompt engineering assistant. Your task is to generate a highly effective, structured prompt that guides toward professional-quality results. The final prompt you generate MUST be in {TARGET_LANGUAGE}. Do not add any explanatory text before or after the generated prompt. Only output the prompt itself, adhering strictly to the provided template structure.",
    
    userQueryHeader: "Please generate a structured prompt. Here are the details:",
    rawRequestLabel: "User's Goal / Raw Request:",
    promptTypeLabel: "Chosen Prompt Structure Type:",
    domainLabel: "Domain:",
    outputLengthLabel: "Desired Output Length for the AI using the generated prompt:",
    expertRoleLabel: "Expert Role for the AI using the generated prompt:",
    missionLabel: "Main Mission for the AI using the generated prompt:",
    constraintsLabel: "Constraints for the AI using the generated prompt (one per line):",
    noneSpecified: "None specified",
    finalPromptLangLabel: "The language for the final prompt itself MUST be: {TARGET_LANGUAGE}.",
    constructPromptInstruction: "Now, based on whether the type is MVP or AGENTIC, construct the prompt using the following templates and information.",
    
    // Enhanced MVP Section
    mvpTemplateHeader: "For an \"MVP\" type prompt, use this template:",
    mvpSystemRole: "You are an excellent {expertRolePlaceholder}: knowledgeable, precise, pedagogical. Your mission is to {missionPlaceholder}.",
    mvpExpertPlaceholder: "Expert",
    mvpMissionPlaceholder: "help effectively",
    
    // Enhanced Methodology for MVP
    mvpMethodologyHeader: "DETAILED METHODOLOGY - Follow this structured approach:",
    mvpAnalysisHeader: "1. IN-DEPTH ANALYSIS:",
    mvpAnalysisTasks: [
      "Meticulously analyze all elements provided in the request above",
      "Identify explicit and implicit objectives, quality criteria, and success metrics",
      "Note technical, creative, and logistical constraints to be respected", 
      "Evaluate context, underlying challenges, and optimization opportunities",
      "Determine the most appropriate resources, tools, and approaches"
    ],
    mvpPlanningHeader: "2. STRATEGIC PLANNING:",
    mvpPlanningTasks: [
      "Consider multiple methodological approaches to address the request optimally",
      "Rigorously evaluate advantages, disadvantages, and implications of each strategy",
      "Select the most appropriate approach and formulate clear justification for this choice",
      "Plan logical structure, progression, and optimal organization of the deliverable",
      "Anticipate execution challenges and prepare adaptation strategies if necessary"
    ],
    mvpExecutionHeader: "3. PROFESSIONAL EXECUTION:",
    mvpExecutionTasks: [
      "Produce a deliverable organized according to clear professional architecture",
      "Use premium formatting with appropriate sections, subsections, and structural elements",
      "Integrate concrete examples, evidence, data, and relevant references to support quality",
      "Scrupulously respect all constraints, specifications, and formulated requirements",
      "Systematically aim for professional-level quality that exceeds standard expectations",
      "Personalize content to maximize its specific relevance and added value"
    ],
    
    mvpExpectedOutputFormat: "Expected output format:",
    mvpLength: "Length:",
    mvpStyle: "Style: Clear and structured",
    mvpLanguage: "Language: {TARGET_LANGUAGE}",
    
    // Fixed Example Instruction  
    mvpExampleInstruction: "(Generate a concrete example showing the EXACT format of the expected output beginning. Do NOT describe the process or explain what the AI will do. Show the direct start of the final deliverable. Examples: For podcast → actual dialogue lines ('Voice 1: Welcome everyone to today's show...'), for lesson plan → actual lesson structure ('LESSON: [Title] | OBJECTIVES: Students will be able to... | MODULE 1: [Content]...'), for analysis → actual analysis format ('EXECUTIVE SUMMARY: This analysis reveals... | KEY FINDINGS: 1. [Primary insight]...'). The example must be a direct sample of the deliverable, not a process description.)",
    
    mvpFooter: "Ensure the entire output is *only* the prompt text, starting with \"<System>:\" and ending appropriately based on the template. Do not add any other commentary.",
    
    // Enhanced AGENTIC Section
    agenticTemplateHeader: "For an \"AGENTIC\" type prompt, use this template. This prompt is for an AI capable of autonomous action, thinking, and iteration. It MUST include self-assessment capabilities.",
    agenticTitleInstruction: "[Generate a concise and descriptive title (max 5-7 words) derived from the user's raw request.]",
    agenticRole: "{expertRolePlaceholder} (Agentic AI)",
    agenticExpertPlaceholder: "Expert Analyst", 
    agenticNote: "*Note: \"Agentic AI\" means an AI capable of acting autonomously, thinking, and iterating on its work.*",
    agenticContext: "Context:",
    agenticInstructionsHeader: "Instructions:",
    
    // Same detailed methodology for AGENTIC (reusing MVP tasks)
    agenticAnalysisHeader: "1. IN-DEPTH ANALYSIS:",
    agenticAnalysisTasks: [
      "Meticulously analyze all elements provided related to the Context above",
      "Identify explicit and implicit objectives, quality criteria, and success metrics",
      "Note technical, creative, and logistical constraints to be respected",
      "Evaluate context, underlying challenges, and optimization opportunities", 
      "Determine the most appropriate resources, tools, and approaches"
    ],
    agenticThinkingHeader: "2. STRATEGIC PLANNING:",
    agenticThinkingTasks: [
      "Consider multiple methodological approaches to address the Context optimally",
      "Rigorously evaluate advantages, disadvantages, and implications of each strategy",
      "Select the most appropriate approach and formulate clear justification for this choice",
      "Plan logical structure, progression, and optimal organization of the deliverable",
      "Anticipate execution challenges and prepare adaptation strategies if necessary"
    ],
    agenticDevelopmentHeader: "3. PROFESSIONAL EXECUTION:",
    agenticDevelopmentTasks: [
      "Produce a deliverable organized according to clear professional architecture",
      "Use premium formatting with appropriate sections, subsections, and structural elements", 
      "Integrate concrete examples, evidence, data, and relevant references to support quality",
      "Scrupulously respect all constraints, specifications, and formulated requirements",
      "Systematically aim for professional-level quality that exceeds standard expectations",
      "Personalize content to maximize its specific relevance and added value"
    ],
    
    // Self-Assessment (AGENTIC only)
    agenticSelfAssessmentHeader: "4. SELF-ASSESSMENT AND CONTINUOUS IMPROVEMENT:",
    agenticSelfAssessmentQuestion1: "At the end of its work, the AI executing this prompt **must always ask the user verbatim**:\n    \"🤔 Would you like me to evaluate this result against key criteria and provide suggestions for improvement? (Yes/No)\"",
    agenticSelfAssessmentInstruction: "If the user responds \"Yes\" (or similar affirmative), the AI should then perform a self-assessment using the following evaluation method, presenting it in a table:",
    agenticEvaluationCriteria: {
        education: ['Pedagogical Clarity', 'Level Appropriateness', 'Learner Engagement', 'Logical Progression'],
        technical: ['Technical Accuracy', 'Completeness of Analysis', 'Rigorous Methodology', 'Actionable Recommendations'],
        other: ['Originality', 'Coherence', 'Impact', 'Quality of Execution']
    },
    agenticEvalTableHeader: "| Criterion                     | Rating (/10) | Justification for Rating | Concrete Suggestions for Improvement |\n    |-------------------------------|--------------|--------------------------|--------------------------------------|",
    agenticSelfAssessmentQuestion2: "After presenting the evaluation, the AI **must also ask the user verbatim**:\n    \"Based on the evaluation above, would you like me to attempt to improve the draft? (Yes/No)\"",
    agenticFooter: "Ensure the entire output is *only* the prompt text, starting with \"Title:\" and ending appropriately based on the template. Do not add any other commentary.",
  },
  
  fr: {
    systemInstructionBase: "Vous êtes un assistant expert en ingénierie de prompts. Votre tâche est de générer un prompt structuré, hautement efficace, qui guide vers des résultats de qualité professionnelle. Le prompt final que vous générez DOIT être en {TARGET_LANGUAGE}. N'ajoutez aucun texte explicatif avant ou après le prompt généré. Ne retournez que le prompt lui-même, en respectant strictement la structure du modèle fourni.",
    
    userQueryHeader: "Veuillez générer un prompt structuré. Voici les détails :",
    rawRequestLabel: "Objectif / Demande brute de l'utilisateur :",
    promptTypeLabel: "Type de structure de prompt choisi :",
    domainLabel: "Domaine :",
    outputLengthLabel: "Longueur de sortie souhaitée pour l'IA utilisant le prompt généré :",
    expertRoleLabel: "Rôle d'expert pour l'IA utilisant le prompt généré :",
    missionLabel: "Mission principale pour l'IA utilisant le prompt généré :",
    constraintsLabel: "Contraintes pour l'IA utilisant le prompt généré (une par ligne) :",
    noneSpecified: "Aucune spécifiée",
    finalPromptLangLabel: "La langue du prompt final lui-même DOIT être : {TARGET_LANGUAGE}.",
    constructPromptInstruction: "Maintenant, selon que le type est MVP ou AGENTIQUE, construisez le prompt en utilisant les modèles et informations suivants.",
    
    // Enhanced MVP Section - French
    mvpTemplateHeader: "Pour un prompt de type \"MVP\", utilisez ce modèle :",
    mvpSystemRole: "Vous êtes un excellent {expertRolePlaceholder} : compétent, précis, pédagogue. Votre mission est d'{missionPlaceholder}.",
    mvpExpertPlaceholder: "Expert",
    mvpMissionPlaceholder: "aider efficacement",
    
    // Enhanced Methodology for MVP - French
    mvpMethodologyHeader: "MÉTHODOLOGIE DÉTAILLÉE - Suivez cette approche structurée :",
    mvpAnalysisHeader: "1. ANALYSE APPROFONDIE :",
    mvpAnalysisTasks: [
      "Analysez méticuleusement tous les éléments fournis dans la demande ci-dessus",
      "Identifiez les objectifs explicites et implicites, critères de qualité et métriques de réussite",
      "Notez les contraintes techniques, créatives et logistiques à respecter",
      "Évaluez le contexte, les défis sous-jacents et les opportunités d'optimisation",
      "Déterminez les ressources, outils et approches les plus appropriés"
    ],
    mvpPlanningHeader: "2. PLANIFICATION STRATÉGIQUE :",
    mvpPlanningTasks: [
      "Considérez de multiples approches méthodologiques pour aborder la demande de manière optimale",
      "Évaluez rigoureusement les avantages, inconvénients et implications de chaque stratégie",
      "Sélectionnez l'approche la plus appropriée et formulez une justification claire de ce choix",
      "Planifiez la structure logique, la progression et l'organisation optimale du livrable",
      "Anticipez les défis d'exécution et préparez des stratégies d'adaptation si nécessaire"
    ],
    mvpExecutionHeader: "3. EXÉCUTION PROFESSIONNELLE :",
    mvpExecutionTasks: [
      "Produisez un livrable organisé selon une architecture professionnelle claire",
      "Utilisez un formatage premium avec sections, sous-sections et éléments de structuration appropriés",
      "Intégrez des exemples concrets, preuves, données et références pertinentes pour étayer la qualité",
      "Respectez scrupuleusement toutes les contraintes, spécifications et exigences formulées",
      "Visez systématiquement un niveau de qualité professionnel qui dépasse les attentes standard",
      "Personnalisez le contenu pour maximiser sa pertinence et sa valeur ajoutée spécifique"
    ],
    
    mvpExpectedOutputFormat: "Format de sortie attendu :",
    mvpLength: "Longueur :",
    mvpStyle: "Style : Clair et structuré",
    mvpLanguage: "Langue : {TARGET_LANGUAGE}",
    
    // Fixed Example Instruction - French
    mvpExampleInstruction: "(Générez un exemple concret montrant le FORMAT EXACT du début du livrable attendu. NE PAS décrire le processus ou expliquer ce que l'IA va faire. Montrez directement le début du résultat final. Exemples : Pour podcast → lignes de dialogue réelles ('Voix 1: Bienvenue dans cette émission...'), pour plan de cours → structure de cours réelle ('COURS: [Titre] | OBJECTIFS: Les apprenants seront capables de... | MODULE 1: [Contenu]...'), pour analyse → format d'analyse réel ('SYNTHÈSE EXÉCUTIVE: Cette analyse révèle... | POINTS CLÉS: 1. [Insight principal]...'). L'exemple doit être un échantillon direct du livrable, pas une description du processus.)",
    
    mvpFooter: "Assurez-vous que l'ensemble de la sortie soit *uniquement* le texte du prompt, commençant par \"<System>:\" et se terminant de manière appropriée selon le modèle. N'ajoutez aucun autre commentaire.",
    
    // Enhanced AGENTIC Section - French (same structure, with self-assessment)
    agenticTemplateHeader: "Pour un prompt de type \"AGENTIQUE\", utilisez ce modèle. Ce prompt est destiné à une IA capable d'action autonome, de réflexion et d'itération. Il DOIT inclure des capacités d'auto-évaluation.",
    agenticTitleInstruction: "[Générez un titre concis et descriptif (max 5-7 mots) dérivé de la demande brute de l'utilisateur.]",
    agenticRole: "{expertRolePlaceholder} (IA Agentique)",
    agenticExpertPlaceholder: "Analyste Expert",
    agenticNote: "*Note : \"IA Agentique\" signifie une IA capable d'agir de manière autonome, de réfléchir et d'itérer sur son travail.*",
    agenticContext: "Contexte :",
    agenticInstructionsHeader: "Instructions :",
    
    // Same detailed methodology for AGENTIC - French
    agenticAnalysisHeader: "1. ANALYSE APPROFONDIE DES INFORMATIONS FOURNIES :",
    agenticAnalysisTasks: [
      "Analysez méticuleusement tous les éléments fournis relatifs au Contexte ci-dessus",
      "Identifiez les objectifs explicites et implicites, critères de qualité et métriques de réussite",
      "Notez les contraintes techniques, créatives et logistiques à respecter",
      "Évaluez le contexte, les défis sous-jacents et les opportunités d'optimisation",
      "Déterminez les ressources, outils et approches les plus appropriés"
    ],
    agenticThinkingHeader: "2. RÉFLEXION APPROFONDIE & PLANIFICATION :",
    agenticThinkingTasks: [
      "Considérez de multiples approches méthodologiques pour aborder le Contexte de manière optimale",
      "Évaluez rigoureusement les avantages, inconvénients et implications de chaque stratégie",
      "Sélectionnez l'approche la plus appropriée et formulez une justification claire de ce choix",
      "Planifiez la structure logique, la progression et l'organisation optimale du livrable",
      "Anticipez les défis d'exécution et préparez des stratégies d'adaptation si nécessaire"
    ],
    agenticDevelopmentHeader: "3. DÉVELOPPEMENT STRUCTURÉ & EXÉCUTION :",
    agenticDevelopmentTasks: [
      "Produisez un livrable organisé selon une architecture professionnelle claire",
      "Utilisez un formatage premium avec sections, sous-sections et éléments de structuration appropriés",
      "Intégrez des exemples concrets, preuves, données et références pertinentes pour étayer la qualité",
      "Respectez scrupuleusement toutes les contraintes, spécifications et exigences formulées",
      "Visez systématiquement un niveau de qualité professionnel qui dépasse les attentes standard",
      "Personnalisez le contenu pour maximiser sa pertinence et sa valeur ajoutée spécifique"
    ],
    
    // Self-Assessment (AGENTIC only) - French
    agenticSelfAssessmentHeader: "4. AUTO-ÉVALUATION ET AMÉLIORATION CONTINUE :",
    agenticSelfAssessmentQuestion1: "À la fin de son travail, l'IA exécutant ce prompt **doit toujours demander à l'utilisateur textuellement** :\n    \"🤔 Souhaitez-vous que j'évalue ce résultat par rapport à des critères clés et que je fournisse des suggestions d'amélioration ? (Oui/Non)\"",
    agenticSelfAssessmentInstruction: "Si l'utilisateur répond \"Oui\" (ou une affirmation similaire), l'IA doit alors effectuer une auto-évaluation en utilisant la méthode d'évaluation suivante, en la présentant dans un tableau :",
    agenticEvaluationCriteria: {
        education: ['Clarté Pédagogique', 'Adéquation au Niveau', 'Engagement de l\'Apprenant', 'Progression Logique'],
        technical: ['Exactitude Technique', 'Complétude de l\'Analyse', 'Méthodologie Rigoureuse', 'Recommandations Actionnables'],
        other: ['Originalité', 'Cohérence', 'Impact', 'Qualité d\'Exécution']
    },
    agenticEvalTableHeader: "| Critère                       | Note (/10)   | Justification de la Note | Suggestions Concrètes d'Amélioration |\n    |-------------------------------|--------------|--------------------------|--------------------------------------|",
    agenticSelfAssessmentQuestion2: "Après avoir présenté l'évaluation, l'IA **doit également demander à l'utilisateur textuellement** :\n    \"Sur la base de l'évaluation ci-dessus, souhaitez-vous que j'essaie d'améliorer le brouillon ? (Oui/Non)\"",
    agenticFooter: "Assurez-vous que l'ensemble de la sortie soit *uniquement* le texte du prompt, commençant par \"Titre:\" et se terminant de manière appropriée selon le modèle. N'ajoutez aucun autre commentaire.",
  }
};

const GEMINI_MODEL_NAME = 'gemini-2.5-pro-preview-05-06'; // As per user request

export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;
  const API_KEY = env.API_KEY;

  if (!API_KEY) {
    return new Response(JSON.stringify({ error: "API_KEY is not configured in the server environment." }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let params: GeneratePromptParams;
  try {
    params = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: "Invalid JSON in request body." }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  
  const tMeta = metaPromptTranslations[params.language] || metaPromptTranslations.en;
  const tApp = appTranslations[params.language] || appTranslations.en;

  const ai = new GoogleGenAI({ apiKey: API_KEY });

  const {
    rawRequest,
    promptType,
    domain,
    language, // language of the UI, and thus the meta-prompt
    outputLength,
    expertRole,
    mission,
    constraints,
  } = params;

  const finalPromptTargetLanguageString = language === 'fr' ? 'Français' : 'English';
  const formattedConstraints = constraints.split('\n').filter(c => c.trim()).map(c => `- ${c.trim()}`).join('\n');
  
  // Enhanced system instruction with language replacement
  let systemInstruction = tMeta.systemInstructionBase.replace('{TARGET_LANGUAGE}', finalPromptTargetLanguageString);
  
  let userQuery = `
${tMeta.userQueryHeader}

${tMeta.rawRequestLabel}
"${rawRequest}"

${tMeta.promptTypeLabel} ${promptType}
${tMeta.domainLabel} ${domain}
${tMeta.outputLengthLabel} ${outputLength}
${tMeta.expertRoleLabel} ${expertRole || (promptType === 'MVP' ? tMeta.mvpExpertPlaceholder : tMeta.agenticExpertPlaceholder)}
${tMeta.missionLabel} ${mission || tMeta.mvpMissionPlaceholder}
${tMeta.constraintsLabel}
${constraints ? formattedConstraints : tMeta.noneSpecified}
${tMeta.finalPromptLangLabel.replace('{TARGET_LANGUAGE}', finalPromptTargetLanguageString)}

${tMeta.constructPromptInstruction}
`;

  if (promptType === 'MVP') {
    userQuery += `
${tMeta.mvpTemplateHeader}

<System>:
${tMeta.mvpSystemRole
    .replace('{expertRolePlaceholder}', expertRole || tMeta.mvpExpertPlaceholder)
    .replace('{missionPlaceholder}', mission || tMeta.mvpMissionPlaceholder)}

<User>:
${rawRequest}

${tMeta.mvpMethodologyHeader}

${tMeta.mvpAnalysisHeader}
${tMeta.mvpAnalysisTasks.map(task => `   • ${task}`).join('\n')}

${tMeta.mvpPlanningHeader}
${tMeta.mvpPlanningTasks.map(task => `   • ${task}`).join('\n')}

${tMeta.mvpExecutionHeader}
${tMeta.mvpExecutionTasks.map(task => `   • ${task}`).join('\n')}

Contraintes spécifiques :
${constraints ? formattedConstraints : tMeta.noneSpecified}

${tMeta.mvpExpectedOutputFormat}
- ${tMeta.mvpLength} ${outputLength}
- ${tMeta.mvpStyle}
- ${tMeta.mvpLanguage.replace('{TARGET_LANGUAGE}', finalPromptTargetLanguageString)}

<Example>:
${tMeta.mvpExampleInstruction}

IMPORTANT: L'exemple ci-dessus doit montrer le format de sortie réel - les premières lignes de ce que l'IA devrait produire. NE PAS générer une description de ce que l'IA va faire. Montrer le début concret du livrable.

${tMeta.mvpFooter}
`;
  } else { // AGENTIC
    const criteriaDomain = (domain === 'education' || domain === 'technical') ? domain : 'other';
    const evaluationCriteriaList = tMeta.agenticEvaluationCriteria[criteriaDomain];
    
    const criteriaTableMarkdown = evaluationCriteriaList.map(c => `| ${c.padEnd(29)} |              |                          |                                      |`).join('\n');

    userQuery += `
${tMeta.agenticTemplateHeader}

Title: ${tMeta.agenticTitleInstruction}

Role: ${tMeta.agenticRole.replace('{expertRolePlaceholder}', expertRole || tMeta.agenticExpertPlaceholder)}
${tMeta.agenticNote}

${tMeta.agenticContext}
${rawRequest}

Contraintes spécifiques :
${constraints ? formattedConstraints : tMeta.noneSpecified}

${tMeta.agenticInstructionsHeader}

${tMeta.agenticAnalysisHeader}
${tMeta.agenticAnalysisTasks.map(task => `    • ${task}`).join('\n')}

${tMeta.agenticThinkingHeader}
${tMeta.agenticThinkingTasks.map(task => `    • ${task}`).join('\n')}

${tMeta.agenticDevelopmentHeader}
${tMeta.agenticDevelopmentTasks.map(task => `    • ${task}`).join('\n')}

EXIGENCE DE QUALITÉ: Produisez un livrable de niveau professionnel qui dépasse les attentes standard en termes de structure, personnalisation et valeur ajoutée.

${tMeta.agenticSelfAssessmentHeader}
    ${tMeta.agenticSelfAssessmentQuestion1}

    ${tMeta.agenticSelfAssessmentInstruction}
    ${tMeta.agenticEvalTableHeader}
${criteriaTableMarkdown}

    ${tMeta.agenticSelfAssessmentQuestion2}

${tMeta.agenticFooter}
`;
  }

  try {
     const result = await ai.models.generateContent({
        model: GEMINI_MODEL_NAME,
        contents: userQuery,
        config: {
            systemInstruction: systemInstruction,
        }
     });
     
     if (result && typeof result.text === 'string') {
        return new Response(JSON.stringify({ prompt: result.text }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
     } else {
        console.error("Gemini API returned an invalid response structure or no text:", result);
        return new Response(JSON.stringify({ error: tApp.generation.error }), { // Use appTranslations for user
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
     }
  } catch (error: any) {
    console.error("Error generating prompt with Gemini in Worker:", error);
    let userFriendlyError = tApp.generation.error; // Default from app translations
    
    // It's better to use specific error codes if Gemini API provides them,
    // but for now, we'll use the error message if it exists.
    if (error?.message) {
        if (error.message.includes('API key not valid') || error.message.includes('API_KEY_INVALID')) {
             userFriendlyError = appTranslations[params.language]?.notifications?.apiError || "Gemini API Error: API key not valid. Please check your configuration.";
        } else if (error.message.toLowerCase().includes('quota')) {
            userFriendlyError = appTranslations[params.language]?.notifications?.apiError || "Gemini API Error: Quota exceeded. Please try again later.";
        } else {
            userFriendlyError = `${tApp.generation.error} - ${error.message}`;
        }
    }
    return new Response(JSON.stringify({ error: userFriendlyError, details: error?.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
