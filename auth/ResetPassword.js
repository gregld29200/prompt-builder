import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext.js';

const ResetPassword = ({ onBackToLogin, translations }) => {
  const { login } = useAuth();
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState('');
  const [validationErrors, setValidationErrors] = useState([]);

  // Extract token from URL on component mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const urlToken = urlParams.get('token');
    
    if (urlToken) {
      setToken(urlToken);
    } else {
      setError(translations.auth.resetPassword.noToken);
    }
  }, [translations]);

  // Validate password in real-time
  useEffect(() => {
    if (password) {
      const errors = [];
      
      if (password.length < 12) {
        errors.push(translations.auth.resetPassword.validation.minLength);
      }
      
      if (!/[A-Z]/.test(password)) {
        errors.push(translations.auth.resetPassword.validation.uppercase);
      }
      
      if (!/[a-z]/.test(password)) {
        errors.push(translations.auth.resetPassword.validation.lowercase);
      }
      
      if (!/\d/.test(password)) {
        errors.push(translations.auth.resetPassword.validation.number);
      }
      
      if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push(translations.auth.resetPassword.validation.special);
      }
      
      setValidationErrors(errors);
    } else {
      setValidationErrors([]);
    }
  }, [password, translations]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!token) {
      setError(translations.auth.resetPassword.noToken);
      return;
    }

    if (!password || !confirmPassword) {
      setError(translations.auth.resetPassword.fieldsRequired);
      return;
    }

    if (password !== confirmPassword) {
      setError(translations.auth.resetPassword.passwordMismatch);
      return;
    }

    if (validationErrors.length > 0) {
      setError(translations.auth.resetPassword.weakPassword);
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          token,
          password
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Auto-login user after successful password reset
        if (data.token && data.user) {
          localStorage.setItem('teachinspire-auth-token', data.token);
          localStorage.setItem('teachinspire-user', JSON.stringify(data.user));
        }
        
        setIsSuccess(true);
        
        // Redirect to app after 2 seconds - the parent component will handle this
        setTimeout(() => {
          onBackToLogin();
        }, 2000);
      } else {
        setError(data.error?.message || translations.auth.resetPassword.errorGeneric);
      }
    } catch (error) {
      console.error('Reset password error:', error);
      setError(translations.auth.resetPassword.errorGeneric);
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
          }, translations.auth.resetPassword.successTitle),
          React.createElement('p', {
            key: 'success-message',
            className: 'text-brand-muted-text mb-6'
          }, translations.auth.resetPassword.successMessage),
          React.createElement('div', {
            key: 'loading-indicator',
            className: 'flex items-center justify-center'
          }, [
            React.createElement('div', {
              key: 'spinner',
              className: 'animate-spin rounded-full h-6 w-6 border-b-2 border-brand-primary-accent'
            }),
            React.createElement('span', {
              key: 'redirect-text',
              className: 'ml-2 text-brand-muted-text'
            }, translations.auth.resetPassword.redirecting)
          ])
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
          }, translations.auth.resetPassword.title),
          React.createElement('p', {
            key: 'subtitle',
            className: 'text-brand-muted-text'
          }, translations.auth.resetPassword.subtitle)
        ]),
        
        React.createElement('form', {
          key: 'form',
          onSubmit: handleSubmit,
          className: 'space-y-6'
        }, [
          React.createElement('div', {
            key: 'password-field'
          }, [
            React.createElement('label', {
              key: 'password-label',
              htmlFor: 'password',
              className: 'block text-sm font-medium text-brand-text mb-2'
            }, translations.auth.resetPassword.passwordLabel),
            React.createElement('input', {
              key: 'password-input',
              type: 'password',
              id: 'password',
              value: password,
              onChange: (e) => setPassword(e.target.value),
              placeholder: translations.auth.resetPassword.passwordPlaceholder,
              className: 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-brand-primary-accent focus:border-transparent transition-colors font-inter',
              disabled: isLoading,
              required: true
            })
          ]),
          
          React.createElement('div', {
            key: 'confirm-password-field'
          }, [
            React.createElement('label', {
              key: 'confirm-password-label',
              htmlFor: 'confirmPassword',
              className: 'block text-sm font-medium text-brand-text mb-2'
            }, translations.auth.resetPassword.confirmPasswordLabel),
            React.createElement('input', {
              key: 'confirm-password-input',
              type: 'password',
              id: 'confirmPassword',
              value: confirmPassword,
              onChange: (e) => setConfirmPassword(e.target.value),
              placeholder: translations.auth.resetPassword.confirmPasswordPlaceholder,
              className: 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-brand-primary-accent focus:border-transparent transition-colors font-inter',
              disabled: isLoading,
              required: true
            })
          ]),
          
          // Password validation feedback
          validationErrors.length > 0 && React.createElement('div', {
            key: 'validation-errors',
            className: 'bg-yellow-50 border border-yellow-200 rounded-lg p-4'
          }, [
            React.createElement('h4', {
              key: 'validation-title',
              className: 'text-sm font-medium text-yellow-800 mb-2'
            }, translations.auth.resetPassword.passwordRequirements),
            React.createElement('ul', {
              key: 'validation-list',
              className: 'text-sm text-yellow-700 space-y-1'
            }, validationErrors.map((error, index) => 
              React.createElement('li', {
                key: `validation-${index}`,
                className: 'flex items-center'
              }, [
                React.createElement('span', {
                  key: 'bullet',
                  className: 'w-1 h-1 bg-yellow-600 rounded-full mr-2'
                }),
                error
              ])
            ))
          ]),
          
          error && React.createElement('div', {
            key: 'error',
            className: 'bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm'
          }, error),
          
          React.createElement('button', {
            key: 'submit-button',
            type: 'submit',
            disabled: isLoading || validationErrors.length > 0 || !token,
            className: `w-full bg-gradient-to-r from-brand-primary-accent to-brand-secondary-accent text-white py-3 px-6 rounded-full font-inter font-semibold transition-all duration-200 transform ${(isLoading || validationErrors.length > 0 || !token) ? 'opacity-50 cursor-not-allowed' : 'hover:shadow-lg hover:scale-105'}`
          }, isLoading ? translations.auth.resetPassword.resetting : translations.auth.resetPassword.resetButton),
          
          React.createElement('div', {
            key: 'back-link',
            className: 'text-center'
          }, [
            React.createElement('button', {
              key: 'back-button',
              type: 'button',
              onClick: onBackToLogin,
              className: 'text-brand-primary-accent hover:text-brand-secondary-accent transition-colors font-medium text-sm'
            }, translations.auth.resetPassword.backToLogin)
          ])
        ])
      ])
    ])
  ]);
};

export default ResetPassword;