// Simplified generate-prompt.ts - same pattern as auth endpoints

import { GoogleGenAI } from "@google/genai";
import type { Language, Domain, OutputLength, PromptType } from '../../types';
import { translations as appTranslations } from '../../constants';

// JWT verification function (same as prompts.ts)
async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error('Invalid token format');
    }
    
    // Verify signature
    const encoder = new TextEncoder();
    const message = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(message));
    
    if (!isValid) {
      throw new Error('Invalid signature');
    }
    
    // Parse payload
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    
    return payload;
  } catch (error) {
    throw new Error('Token verification failed');
  }
}

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

// Enhanced metaPromptTranslations with detailed methodology for both approaches
const metaPromptTranslations = {
  en: {
    systemInstructionBase: "You are an expert prompt engineer. Generate a complete, executable prompt following the exact format: <System>, <User>, <Example>. The final prompt must be in {TARGET_LANGUAGE} and ready for immediate use by an AI. Include detailed methodology in the User section and compelling examples. Output ONLY the prompt text - no meta-commentary or explanations outside the prompt structure.",
    
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
    mvpTemplateHeader: "For an \"MVP\" type prompt, generate a complete executable prompt:",
    mvpGenerateInstruction: "Generate a complete, executable prompt using this exact structure:",
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
    mvpExampleInstruction: "Show the exact beginning of the expected deliverable - first 3-5 lines of actual output, not process description. Examples: For podcast → 'Voice 1: Welcome everyone to today's show...', for lesson plan → 'LESSON: [Title] | OBJECTIVES: Students will be able to...', for analysis → 'EXECUTIVE SUMMARY: This analysis reveals...'. The example must be a direct sample of the deliverable.",
    
    mvpFooter: "CRITICAL: Generate ONLY the complete prompt above with <System>, <User>, and <Example> sections. Do not add meta-commentary or explanations outside the prompt structure.",
    
    // Enhanced AGENTIC Section
    agenticTemplateHeader: "For an \"AGENTIC\" type prompt, generate a complete executable prompt with self-assessment capabilities:",
    agenticGenerateInstruction: "Generate a complete, executable AGENTIC prompt using this exact structure:",
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
    agenticFooter: "CRITICAL: Generate ONLY the complete prompt above with Title, <System>, <User>, and <Example> sections. Do not add meta-commentary or explanations outside the prompt structure.",
  },
  
  fr: {
    systemInstructionBase: "Vous êtes un ingénieur de prompts expert. Générez un prompt complet et exécutable suivant exactement le format : <System>, <User>, <Example>. Le prompt final doit être en {TARGET_LANGUAGE} et prêt à être utilisé immédiatement par une IA. Incluez une méthodologie détaillée dans la section User et des exemples convaincants. Ne générez QUE le texte du prompt - aucun méta-commentaire ou explication en dehors de la structure du prompt.",
    
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
    constructPromptInstruction: "Maintenant, selon que le type est MVP ou AGENTIQUE, générez le prompt en utilisant les modèles et informations suivants.",
    
    // Enhanced MVP Section - French
    mvpTemplateHeader: "Pour un prompt de type \"MVP\", générez un prompt exécutable complet :",
    mvpGenerateInstruction: "Générez un prompt complet et exécutable en utilisant exactement cette structure :",
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
    mvpExampleInstruction: "Montrez le début exact du livrable attendu - les 3-5 premières lignes de sortie réelle, pas une description de processus. Exemples : Pour podcast → 'Voix 1: Bienvenue dans cette émission...', pour plan de cours → 'COURS: [Titre] | OBJECTIFS: Les apprenants seront capables de...', pour analyse → 'SYNTHÈSE EXÉCUTIVE: Cette analyse révèle...'. L'exemple doit être un échantillon direct du livrable.",
    
    mvpFooter: "CRITIQUE: Générez UNIQUEMENT le prompt complet ci-dessus avec les sections <System>, <User>, et <Example>. N'ajoutez aucun méta-commentaire ou explication en dehors de la structure du prompt.",
    
    // Enhanced AGENTIC Section - French (same structure, with self-assessment)
    agenticTemplateHeader: "Pour un prompt de type \"AGENTIQUE\", générez un prompt exécutable complet avec capacités d'auto-évaluation :",
    agenticGenerateInstruction: "Générez un prompt AGENTIQUE complet et exécutable en utilisant exactement cette structure :",
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
    agenticFooter: "CRITIQUE: Générez UNIQUEMENT le prompt complet ci-dessus avec les sections Titre, <System>, <User>, et <Example>. N'ajoutez aucun méta-commentaire ou explication en dehors de la structure du prompt.",
  }
};

const GEMINI_MODEL_NAME = 'gemini-2.5-pro-preview-05-06'; // As per user request

// Simple UUID generator (same as register.ts)
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Build prompt query based on parameters
 */
function buildPromptQuery(params: GeneratePromptParams, tMeta: any): { systemInstruction: string; userQuery: string } {
  const {
    rawRequest,
    promptType,
    domain,
    language,
    outputLength,
    expertRole,
    mission,
    constraints,
  } = params;

  const finalPromptTargetLanguageString = language === 'fr' ? 'Français' : 'English';
  const formattedConstraints = constraints ? 
    constraints.split('\n').filter(c => c.trim()).map(c => `- ${c.trim()}`).join('\n') : '';
  
  // Enhanced system instruction with language replacement
  const systemInstruction = tMeta.systemInstructionBase.replace('{TARGET_LANGUAGE}', finalPromptTargetLanguageString);
  
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

${tMeta.mvpGenerateInstruction}

<System>:
${tMeta.mvpSystemRole
    .replace('{expertRolePlaceholder}', expertRole || tMeta.mvpExpertPlaceholder)
    .replace('{missionPlaceholder}', mission || tMeta.mvpMissionPlaceholder)}

<User>:
${rawRequest}

${tMeta.mvpMethodologyHeader}

${tMeta.mvpAnalysisHeader}
${tMeta.mvpAnalysisTasks.map((task: string) => `• ${task}`).join('\n')}

${tMeta.mvpPlanningHeader}
${tMeta.mvpPlanningTasks.map((task: string) => `• ${task}`).join('\n')}

${tMeta.mvpExecutionHeader}
${tMeta.mvpExecutionTasks.map((task: string) => `• ${task}`).join('\n')}

Contraintes spécifiques :
${constraints ? formattedConstraints : tMeta.noneSpecified}

Format attendu : ${outputLength}, ${tMeta.mvpStyle.toLowerCase()}, ${tMeta.mvpLanguage.replace('{TARGET_LANGUAGE}', finalPromptTargetLanguageString)}

<Example>:
${tMeta.mvpExampleInstruction}

${tMeta.mvpFooter}
`;
  } else { // AGENTIC
    const criteriaDomain = (domain === 'education' || domain === 'technical') ? domain : 'other';
    const evaluationCriteriaList = tMeta.agenticEvaluationCriteria[criteriaDomain];
    
    const criteriaTableMarkdown = evaluationCriteriaList.map((c: string) => 
      `| ${c.padEnd(29)} |              |                          |                                      |`
    ).join('\n');

    userQuery += `
${tMeta.agenticTemplateHeader}

${tMeta.agenticGenerateInstruction}

Title: ${tMeta.agenticTitleInstruction}

<System>:
${tMeta.agenticRole.replace('{expertRolePlaceholder}', expertRole || tMeta.agenticExpertPlaceholder)} ${tMeta.agenticNote} ${language === 'fr' ? 'Votre mission est d\'' : 'Your mission is to '}${mission || tMeta.mvpMissionPlaceholder}.

<User>:
${rawRequest}

${tMeta.agenticInstructionsHeader}

${tMeta.agenticAnalysisHeader}
${tMeta.agenticAnalysisTasks.map((task: string) => `• ${task}`).join('\n')}

${tMeta.agenticThinkingHeader}
${tMeta.agenticThinkingTasks.map((task: string) => `• ${task}`).join('\n')}

${tMeta.agenticDevelopmentHeader}
${tMeta.agenticDevelopmentTasks.map((task: string) => `• ${task}`).join('\n')}

${tMeta.agenticSelfAssessmentHeader}
${tMeta.agenticSelfAssessmentQuestion1}

${tMeta.agenticSelfAssessmentInstruction}
${tMeta.agenticEvalTableHeader}
${criteriaTableMarkdown}

${tMeta.agenticSelfAssessmentQuestion2}

Contraintes spécifiques :
${constraints ? formattedConstraints : tMeta.noneSpecified}

Format attendu : ${outputLength}, ${tMeta.mvpStyle.toLowerCase()}, ${tMeta.mvpLanguage.replace('{TARGET_LANGUAGE}', finalPromptTargetLanguageString)}

<Example>:
${language === 'fr' ? '[Montrez le début exact du livrable attendu avec le format du titre et les premières lignes de contenu réel]' : '[Show the exact beginning of the expected deliverable with the title format and first few lines of actual content]'}

${tMeta.agenticFooter}
`;
  }

  return { systemInstruction, userQuery };
}

export const onRequestPost = async (context: any) => {
  const { request, env } = context;
  
  try {
    console.log('=== GENERATE PROMPT ENDPOINT ===');
    
    // Basic environment check
    if (!env.JWT_SECRET) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'CONFIG_ERROR',
          message: 'JWT configuration missing'
        }
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (!env.API_KEY) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'CONFIG_ERROR',
          message: 'API key configuration missing'
        }
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Get token from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'NO_TOKEN',
          message: 'Authorization token required'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    
    // Verify JWT
    let user;
    try {
      user = await verifyJWT(token, env.JWT_SECRET);
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Parse JSON
    const params: GeneratePromptParams = await request.json();
    console.log('Generating prompt for user:', user.userId);
    
    // Get translations
    const tMeta = metaPromptTranslations[params.language] || metaPromptTranslations.en;
    
    // Build prompt query
    const { systemInstruction, userQuery } = buildPromptQuery(params, tMeta);

    // Initialize Gemini AI
    const ai = new GoogleGenAI({ apiKey: env.API_KEY });

    // Call Gemini API
    const result = await ai.models.generateContent({
      model: GEMINI_MODEL_NAME,
      contents: userQuery,
      config: {
        systemInstruction: systemInstruction,
      }
    });
     
    if (!result || typeof result.text !== 'string') {
      throw new Error('Invalid response from Gemini API');
    }

    console.log('Prompt generated successfully for user:', user.userId);

    return new Response(JSON.stringify({
      success: true,
      prompt: result.text
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error: any) {
    console.error('Generate prompt error:', error);
    
    // Handle specific error types
    let errorResponse = {
      code: 'INTERNAL_ERROR',
      message: 'Unable to generate prompt'
    };

    if (error?.message) {
      if (error.message.includes('API key not valid') || error.message.includes('API_KEY_INVALID')) {
        errorResponse = {
          code: 'API_KEY_ERROR',
          message: 'Service configuration error'
        };
      } else if (error.message.toLowerCase().includes('quota')) {
        errorResponse = {
          code: 'QUOTA_EXCEEDED',
          message: 'Service temporarily unavailable due to high demand'
        };
      }
    }
    
    return new Response(JSON.stringify({
      success: false,
      error: errorResponse
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
