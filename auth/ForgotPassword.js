import React, { useState } from 'react';
import { useLanguage } from '../components/LanguageContext.js';
import apiService from '../services/apiService.js';

const ForgotPassword = ({ onBackToLogin }) => {
  const { translations } = useLanguage();
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!email.trim()) {
      setError(translations.auth.forgotPassword.emailRequired);
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          email: email.trim(),
          language: translations.currentLanguage
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setIsSuccess(true);
      } else {
        setError(data.error?.message || translations.auth.forgotPassword.errorGeneric);
      }
    } catch (error) {
      console.error('Forgot password error:', error);
      setError(translations.auth.forgotPassword.errorGeneric);
    } finally {
      setIsLoading(false);
    }
  };

  if (isSuccess) {
    return React.createElement('div', {
      className: 'min-h-screen bg-brand-bg flex items-center justify-center p-4'
    }, [
      React.createElement('div', {
        key: 'success-container',
        className: 'w-full max-w-md'
      }, [
        React.createElement('div', {
          key: 'success-card',
          className: 'bg-brand-card-bg rounded-lg shadow-brand-lg p-8 text-center'
        }, [
          React.createElement('div', {
            key: 'success-icon',
            className: 'w-16 h-16 bg-brand-success rounded-full flex items-center justify-center mx-auto mb-4'
          }, [
            React.createElement('svg', {
              key: 'check-icon',
              className: 'w-8 h-8 text-white',
              fill: 'none',
              stroke: 'currentColor',
              viewBox: '0 0 24 24'
            }, [
              React.createElement('path', {
                key: 'check-path',
                strokeLinecap: 'round',
                strokeLinejoin: 'round',
                strokeWidth: 2,
                d: 'M5 13l4 4L19 7'
              })
            ])
          ]),
          React.createElement('h2', {
            key: 'success-title',
            className: 'text-2xl font-playfair font-bold text-brand-text mb-4'
          }, translations.auth.forgotPassword.successTitle),
          React.createElement('p', {
            key: 'success-message',
            className: 'text-brand-muted-text mb-6'
          }, translations.auth.forgotPassword.successMessage),
          React.createElement('button', {
            key: 'back-button',
            onClick: onBackToLogin,
            className: 'w-full bg-gradient-to-r from-brand-primary-accent to-brand-secondary-accent text-white py-3 px-6 rounded-full font-inter font-semibold hover:shadow-lg transition-all duration-200 transform hover:scale-105'
          }, translations.auth.forgotPassword.backToLogin)
        ])
      ])
    ]);
  }

  return React.createElement('div', {
    className: 'min-h-screen bg-brand-bg flex items-center justify-center p-4'
  }, [
    React.createElement('div', {
      key: 'form-container',
      className: 'w-full max-w-md'
    }, [
      React.createElement('div', {
        key: 'form-card',
        className: 'bg-brand-card-bg rounded-lg shadow-brand-lg p-8'
      }, [
        React.createElement('div', {
          key: 'header',
          className: 'text-center mb-8'
        }, [
          React.createElement('h2', {
            key: 'title',
            className: 'text-2xl font-playfair font-bold text-brand-text mb-2'
          }, translations.auth.forgotPassword.title),
          React.createElement('p', {
            key: 'subtitle',
            className: 'text-brand-muted-text'
          }, translations.auth.forgotPassword.subtitle)
        ]),
        
        React.createElement('form', {
          key: 'form',
          onSubmit: handleSubmit,
          className: 'space-y-6'
        }, [
          React.createElement('div', {
            key: 'email-field'
          }, [
            React.createElement('label', {
              key: 'email-label',
              htmlFor: 'email',
              className: 'block text-sm font-medium text-brand-text mb-2'
            }, translations.auth.forgotPassword.emailLabel),
            React.createElement('input', {
              key: 'email-input',
              type: 'email',
              id: 'email',
              value: email,
              onChange: (e) => setEmail(e.target.value),
              placeholder: translations.auth.forgotPassword.emailPlaceholder,
              className: 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-brand-primary-accent focus:border-transparent transition-colors font-inter',
              disabled: isLoading,
              required: true
            })
          ]),
          
          error && React.createElement('div', {
            key: 'error',
            className: 'bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm'
          }, error),
          
          React.createElement('button', {
            key: 'submit-button',
            type: 'submit',
            disabled: isLoading,
            className: `w-full bg-gradient-to-r from-brand-primary-accent to-brand-secondary-accent text-white py-3 px-6 rounded-full font-inter font-semibold transition-all duration-200 transform ${isLoading ? 'opacity-50 cursor-not-allowed' : 'hover:shadow-lg hover:scale-105'}`
          }, isLoading ? translations.auth.forgotPassword.sending : translations.auth.forgotPassword.sendButton),
          
          React.createElement('div', {
            key: 'back-link',
            className: 'text-center'
          }, [
            React.createElement('button', {
              key: 'back-button',
              type: 'button',
              onClick: onBackToLogin,
              className: 'text-brand-primary-accent hover:text-brand-secondary-accent transition-colors font-medium text-sm'
            }, translations.auth.forgotPassword.backToLogin)
          ])
        ])
      ])
    ])
  ]);
};

export default ForgotPassword;