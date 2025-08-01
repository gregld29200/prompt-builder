
// File: services/geminiService.js

import { translations } from '../constants.js';
import apiService from './apiService.js';

export const generateStructuredPromptWithGemini = async (params) => {
  const t = translations[params.language] || translations.en;

  try {
    const result = await apiService.makeRequest('/api/generate-prompt', {
      method: 'POST',
      body: JSON.stringify(params),
    });

    if (result.prompt) {
      return result.prompt;
    } else if (result.error) {
      console.error("Error from backend:", result.error);
      throw new Error(result.error);
    } else {
      console.error("Invalid response structure from backend:", result);
      throw new Error(t.generation.error);
    }

  } catch (error) {
    console.error("Error calling /api/generate-prompt or processing response:", error);
    // error.message should now contain the error string thrown from the blocks above
    // or a network error message.
    // The App.js component will catch this and display it.
    // We re-throw to ensure the calling code knows an error occurred.
    // If error.message is already user-friendly (e.g., from backend), it will be used.
    // Otherwise, a more generic message will be formed by the caller.
    throw error; 
  }
};
