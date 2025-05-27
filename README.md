
# Teachinspire Prompt Builder

The Teachinspire Prompt Builder is a web application designed to help users, particularly educators and instructional designers, transform their ideas into structured and effective prompts for AI models like Google's Gemini. It guides users through a process of defining their request, selecting an approach (MVP or Agentic), refining variables, and then generates a tailored prompt.

The application emphasizes the "meta" approach taught in Teachinspire lessons, where AI is used to help construct prompts for AI. It uses a Cloudflare Worker to securely handle API calls to the Google Gemini API.

## Features

*   **Intuitive Interface:** A step-by-step process to build prompts.
*   **Request Analysis:** Automatically analyzes the user's initial request to suggest a domain, complexity, and prompt type.
*   **Two Prompting Approaches:**
    *   **MVP (Minimum Viable Prompt):** For simpler tasks, generating a System-User-Example structure.
    *   **AGENTIC:** For more complex tasks, generating a prompt that instructs an AI to perform self-assessment and iteration.
*   **Variable Refinement:** Allows users to specify domain, output length, expert role, mission, and constraints for the AI.
*   **Secure Gemini API Integration:** Uses a Cloudflare Worker to securely call Google's Gemini API (model: `gemini-2.5-pro-preview-05-06`) for generating the final structured prompt. The API key is handled server-side.
*   **Prompt Library:** Users can save their generated prompts to a local browser storage library and reuse them.
*   **Export & Copy:** Easy options to copy the generated prompt to the clipboard or export it as a text file.
*   **Bilingual Support:** Interface and generated prompts can be in English or French.
*   **Brand Aligned UI:** Adheres to Teachinspire brand guidelines for a professional and approachable look and feel.
*   **Responsive Design:** Works across various screen sizes.

## Tech Stack

*   **Frontend:** React, TypeScript
*   **Backend (Serverless):** Cloudflare Worker (Pages Function) in TypeScript
*   **Styling:** Tailwind CSS (via CDN)
*   **Icons:** Lucide React
*   **AI Model:** Google Gemini API (`gemini-2.5-pro-preview-05-06`)
*   **Module System (Client):** ES Modules with `importmap` (CDN-based dependencies)

## Setup and Running the Application

This application is designed to be deployed to Cloudflare Pages.

**Prerequisites:**

*   A Cloudflare account.
*   A GitHub account to connect your repository to Cloudflare Pages.
*   A Google Gemini API key.

**IMPORTANT: API Key Configuration for Cloudflare Deployment**

The application's backend (Cloudflare Worker) requires a Google Gemini API key to function.

*   The API key **MUST** be set as an environment variable named `API_KEY` in your Cloudflare Pages project settings.
*   Navigate to your Pages project -> Settings -> Environment variables. Add `API_KEY` with your Gemini API key value for both Production and Preview environments.
*   The client-side application **DOES NOT** handle the API key directly.

**How to Deploy to Cloudflare Pages:**

1.  **Push to GitHub:** Ensure all project files are committed to your GitHub repository.
2.  **Connect to Cloudflare Pages:**
    *   In your Cloudflare dashboard, go to "Workers & Pages".
    *   Create a new Pages application and connect it to your GitHub repository.
3.  **Build Settings:**
    *   **Framework Preset:** Select **"None"** (or a Node.js preset if you have more complex build steps in `package.json`). Cloudflare will automatically detect and build the Worker in the `functions` directory.
    *   **Build command:** Can be left blank if no client-side build steps are needed beyond what Cloudflare Pages does automatically.
    *   **Build output directory:** `/` (as `index.html` is at the root).
4.  **Set Environment Variable:** As mentioned above, set your `API_KEY` in the Pages project settings.
5.  **Deploy:** Cloudflare Pages will build and deploy your site, including the serverless function.

**Local Development (Simulating Cloudflare Environment):**

*   For full local testing of the Worker function, you would typically use Cloudflare's `wrangler` CLI.
*   For simpler client-side development (without hitting the actual Worker locally), you can serve `index.html` using a basic HTTP server (`npx serve .`). However, prompt generation will fail as it relies on the `/api/generate-prompt` endpoint that the Worker provides once deployed.
*   The `API_KEY` is not used directly by the client-side code.

## Project Structure

*   `index.html`: The main HTML file for the client-side application.
*   `index.tsx`: The entry point for the React application.
*   `App.tsx`: The main React component.
*   `services/geminiService.ts`: (Client-side) Handles making `fetch` requests to the Cloudflare Worker.
*   `constants.ts`: Shared constants and translations.
*   `types.ts`: TypeScript type definitions.
*   `functions/api/generate-prompt.ts`: **(Cloudflare Worker)** The serverless function that securely calls the Gemini API. Contains the "meta-prompt" logic.
*   `metadata.json`: Application metadata.
*   `README.md`: This file.
*   `.gitignore`: Specifies intentionally untracked files for Git.
*   `LICENSE`: MIT License.
*   `package.json`: Project manifest, including dependencies for the Cloudflare Worker.

## How It Works

1.  **User Input (Client - Step 1-3):** The user interacts with the React frontend, describing their goal and refining variables.
2.  **API Call (Client to Worker):** The client-side `services/geminiService.ts` sends these parameters via a `fetch` POST request to the `/api/generate-prompt` endpoint (our Cloudflare Worker).
3.  **Secure API Call (Worker - Step 4):**
    *   The Cloudflare Worker (`functions/api/generate-prompt.ts`) receives the request.
    *   It securely accesses the `API_KEY` from its environment variables.
    *   It constructs a detailed "meta-prompt" based on the received parameters and the selected UI language.
    *   It calls the Google Gemini API using the `@google/genai` SDK.
4.  **Response (Worker to Client):** The Worker sends the generated prompt (or an error message) back to the client as a JSON response.
5.  **Display & Actions (Client):** The React frontend displays the received prompt. The user can copy, save, or export it.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
