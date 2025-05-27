
// File: services/geminiService.ts

// Removed: import { GoogleGenAI } from "@google/genai";
import type { Language, Domain, OutputLength, PromptType } from '../types';
import { translations } from '../constants'; // Keep for client-side error messages if needed

// Removed: API_KEY, ai initialization, GEMINI_MODEL_NAME, and metaPromptTranslations (this logic is now in the Cloudflare Worker)

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

export const generateStructuredPromptWithGemini = async (params: GeneratePromptParams): Promise<string> => {
  const t = translations[params.language] || translations.en;

  try {
    const response = await fetch('/api/generate-prompt', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
    });

    if (!response.ok) {
      let errorData = { error: t.generation.error, details: response.statusText }; // Default error
      try {
        const parsedError = await response.json();
        if (parsedError && parsedError.error) {
          errorData.error = parsedError.error; // Use error message from backend if available
        }
        if (parsedError && parsedError.details) {
          errorData.details = parsedError.details;
        }
      } catch (e) {
        // If parsing JSON fails, use the default error based on status text
        console.error("Failed to parse error response from backend:", e);
      }
      // Throw an error that can be caught by the caller to display to the user
      throw new Error(errorData.error || errorData.details);
    }

    const result = await response.json();

    if (result.prompt) {
      return result.prompt;
    } else if (result.error) {
      // This case might be redundant if !response.ok already caught it,
      // but good for defense if the server sends 200 OK with an error field.
      console.error("Error from backend (in result.error):", result.error);
      throw new Error(result.error);
    } else {
      // Handle unexpected success response structure
      console.error("Invalid response structure from backend:", result);
      throw new Error(t.generation.error); // Use a generic generation error message
    }

  } catch (error: any) {
    console.error("Error calling /api/generate-prompt or processing response:", error);
    // error.message should now contain the error string thrown from the blocks above
    // or a network error message.
    // The App.tsx component will catch this and display it.
    // We re-throw to ensure the calling code knows an error occurred.
    // If error.message is already user-friendly (e.g., from backend), it will be used.
    // Otherwise, a more generic message will be formed by the caller.
    throw error; 
  }
};
