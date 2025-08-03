import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.js';

// Simple app wrapper for the dedicated app page
const AppWrapper = () => {
  // Get language from URL params or localStorage
  const getInitialLanguage = () => {
    const urlParams = new URLSearchParams(window.location.search);
    const urlLang = urlParams.get('lang');
    const storedLang = localStorage.getItem('preferred-language');
    return urlLang || storedLang || 'fr';
  };

  const [language, setLanguage] = React.useState(getInitialLanguage());

  React.useEffect(() => {
    // Update HTML lang attribute
    document.documentElement.lang = language;
    // Store language preference
    localStorage.setItem('preferred-language', language);
  }, [language]);

  return React.createElement(App, {
    initialLanguage: language,
    onLanguageChange: setLanguage
  });
};

// Mount the app to #root
const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(React.createElement(AppWrapper));
} else {
  console.error('Root container not found');
}