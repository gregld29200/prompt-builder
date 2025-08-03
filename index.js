
import React from 'react';
import { createRoot } from 'react-dom/client';
import { AuthProvider } from './auth/AuthContext.js';
import AuthWrapper from './auth/AuthWrapper.js';
import MainApp from './App.js';

// App component with authentication wrapper
const App = () => {
  return React.createElement(AuthProvider, null,
    React.createElement(AuthWrapper, null,
      React.createElement(MainApp, null)
    )
  );
};

// Mount the app to #app instead of #root
const container = document.getElementById('app');
if (container) {
  const root = createRoot(container);
  root.render(React.createElement(App));
} else {
  console.error('App container not found');
}
