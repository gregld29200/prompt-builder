
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.js';

// Mount the app to #app instead of #root
const container = document.getElementById('app');
if (container) {
  const root = createRoot(container);
  root.render(React.createElement(App));
} else {
  console.error('App container not found');
}
