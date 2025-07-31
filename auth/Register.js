import React, { useState } from 'react';
import { Mail, Lock, Eye, EyeOff, Loader2, AlertCircle, Check } from 'lucide-react';
import { useAuth } from './AuthContext.js';

const Register = ({ onSwitchToLogin, translations }) => {
  const { register } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [validationErrors, setValidationErrors] = useState({});

  const t = translations;

  const validatePassword = (password) => {
    const requirements = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    };
    return requirements;
  };

  const validateForm = () => {
    const errors = {};
    
    // Email validation
    if (!formData.email) {
      errors.email = t.auth.validation.emailRequired;
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errors.email = t.auth.validation.emailInvalid;
    }

    // Password validation
    if (!formData.password) {
      errors.password = t.auth.validation.passwordRequired;
    } else if (formData.password.length < 8) {
      errors.password = t.auth.validation.passwordMinLength8;
    }

    // Confirm password validation
    if (!formData.confirmPassword) {
      errors.confirmPassword = t.auth.validation.confirmPasswordRequired;
    } else if (formData.password !== formData.confirmPassword) {
      errors.confirmPassword = t.auth.validation.passwordsDoNotMatch;
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear validation error for this field
    if (validationErrors[name]) {
      setValidationErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
    
    // Clear confirm password error if passwords now match
    if (name === 'password' && formData.confirmPassword && value === formData.confirmPassword) {
      setValidationErrors(prev => ({
        ...prev,
        confirmPassword: ''
      }));
    }
    
    // Clear general error
    if (error) {
      setError('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const result = await register(formData.email, formData.password);
      
      if (!result.success) {
        setError(result.error || t.auth.errors.registrationFailed);
      }
      // Success is handled by the AuthContext state change
    } catch (err) {
      console.error('Registration error:', err);
      setError(t.auth.errors.registrationFailed);
    } finally {
      setIsLoading(false);
    }
  };

  const passwordRequirements = validatePassword(formData.password);

  return React.createElement("div", { className: "min-h-screen bg-brand-bg flex items-center justify-center px-4 sm:px-6 lg:px-8" },
    React.createElement("div", { className: "max-w-md w-full space-y-8" },
      React.createElement("div", { className: "text-center" },
        React.createElement("img", {
          src: "https://res.cloudinary.com/ducvoebot/image/upload/v1747991665/Teachinspire_logo_transparent_yjt3uf.png",
          alt: "Teachinspire Logo",
          className: "mx-auto h-16 w-auto mb-6"
        }),
        React.createElement("h2", { className: "font-playfair text-3xl font-bold text-brand-text mb-2" }, t.auth.register.title),
        React.createElement("p", { className: "text-brand-muted-text" }, t.auth.register.subtitle)
      ),

      React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand p-8" },
        React.createElement("form", { onSubmit: handleSubmit, className: "space-y-6" },
          // Email field
          React.createElement("div", null,
            React.createElement("label", { 
              htmlFor: "email", 
              className: "block text-sm font-medium text-brand-text mb-2" 
            }, t.auth.fields.email),
            React.createElement("div", { className: "relative" },
              React.createElement("div", { className: "absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" },
                React.createElement(Mail, { className: "h-5 w-5 text-brand-muted-text" })
              ),
              React.createElement("input", {
                id: "email",
                name: "email",
                type: "email",
                autoComplete: "email",
                required: true,
                value: formData.email,
                onChange: handleInputChange,
                className: `block w-full pl-10 pr-3 py-3 border-2 rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-primary-accent text-base ${
                  validationErrors.email 
                    ? 'border-brand-error focus:border-brand-error' 
                    : 'border-gray-300 focus:border-brand-primary-accent'
                }`,
                placeholder: t.auth.placeholders.email
              })
            ),
            validationErrors.email && React.createElement("p", { className: "mt-1 text-sm text-brand-error" }, validationErrors.email)
          ),

          // Password field
          React.createElement("div", null,
            React.createElement("label", { 
              htmlFor: "password", 
              className: "block text-sm font-medium text-brand-text mb-2" 
            }, t.auth.fields.password),
            React.createElement("div", { className: "relative" },
              React.createElement("div", { className: "absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" },
                React.createElement(Lock, { className: "h-5 w-5 text-brand-muted-text" })
              ),
              React.createElement("input", {
                id: "password",
                name: "password",
                type: showPassword ? "text" : "password",
                autoComplete: "new-password",
                required: true,
                value: formData.password,
                onChange: handleInputChange,
                className: `block w-full pl-10 pr-10 py-3 border-2 rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-primary-accent text-base ${
                  validationErrors.password 
                    ? 'border-brand-error focus:border-brand-error' 
                    : 'border-gray-300 focus:border-brand-primary-accent'
                }`,
                placeholder: t.auth.placeholders.password
              }),
              React.createElement("button", {
                type: "button",
                onClick: () => setShowPassword(!showPassword),
                className: "absolute inset-y-0 right-0 pr-3 flex items-center"
              },
                React.createElement(showPassword ? EyeOff : Eye, { 
                  className: "h-5 w-5 text-brand-muted-text hover:text-brand-text" 
                })
              )
            ),
            validationErrors.password && React.createElement("p", { className: "mt-1 text-sm text-brand-error" }, validationErrors.password),
            
            // Password requirements (show when password field is focused or has content)
            formData.password && React.createElement("div", { className: "mt-2 p-3 bg-brand-bg/50 rounded-lg border" },
              React.createElement("p", { className: "text-xs font-medium text-brand-text mb-2" }, t.auth.register.passwordRequirements),
              React.createElement("div", { className: "space-y-1" },
                [
                  { key: 'length', label: t.auth.register.requirements.length, met: passwordRequirements.length },
                  { key: 'lowercase', label: t.auth.register.requirements.lowercase, met: passwordRequirements.lowercase },
                  { key: 'uppercase', label: t.auth.register.requirements.uppercase, met: passwordRequirements.uppercase },
                  { key: 'number', label: t.auth.register.requirements.number, met: passwordRequirements.number },
                  { key: 'special', label: t.auth.register.requirements.special, met: passwordRequirements.special },
                ].map(req => React.createElement("div", { key: req.key, className: "flex items-center gap-2" },
                  React.createElement(Check, { 
                    className: `h-3 w-3 ${req.met ? 'text-brand-success' : 'text-brand-muted-text'}` 
                  }),
                  React.createElement("span", { 
                    className: `text-xs ${req.met ? 'text-brand-success' : 'text-brand-muted-text'}` 
                  }, req.label)
                ))
              )
            )
          ),

          // Confirm Password field
          React.createElement("div", null,
            React.createElement("label", { 
              htmlFor: "confirmPassword", 
              className: "block text-sm font-medium text-brand-text mb-2" 
            }, t.auth.fields.confirmPassword),
            React.createElement("div", { className: "relative" },
              React.createElement("div", { className: "absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" },
                React.createElement(Lock, { className: "h-5 w-5 text-brand-muted-text" })
              ),
              React.createElement("input", {
                id: "confirmPassword",
                name: "confirmPassword",
                type: showConfirmPassword ? "text" : "password",
                autoComplete: "new-password",
                required: true,
                value: formData.confirmPassword,
                onChange: handleInputChange,
                className: `block w-full pl-10 pr-10 py-3 border-2 rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-primary-accent text-base ${
                  validationErrors.confirmPassword 
                    ? 'border-brand-error focus:border-brand-error' 
                    : 'border-gray-300 focus:border-brand-primary-accent'
                }`,
                placeholder: t.auth.placeholders.confirmPassword
              }),
              React.createElement("button", {
                type: "button",
                onClick: () => setShowConfirmPassword(!showConfirmPassword),
                className: "absolute inset-y-0 right-0 pr-3 flex items-center"
              },
                React.createElement(showConfirmPassword ? EyeOff : Eye, { 
                  className: "h-5 w-5 text-brand-muted-text hover:text-brand-text" 
                })
              )
            ),
            validationErrors.confirmPassword && React.createElement("p", { className: "mt-1 text-sm text-brand-error" }, validationErrors.confirmPassword)
          ),

          // General error message
          error && React.createElement("div", { className: "flex items-center gap-2 p-3 bg-brand-error/10 border border-brand-error/20 rounded-lg" },
            React.createElement(AlertCircle, { className: "h-5 w-5 text-brand-error flex-shrink-0" }),
            React.createElement("p", { className: "text-sm text-brand-error" }, error)
          ),

          // Submit button
          React.createElement("button", {
            type: "submit",
            disabled: isLoading,
            className: `w-full flex justify-center items-center gap-2 py-3 px-4 border border-transparent rounded-lg shadow-sm text-white font-medium transition-all ${
              isLoading 
                ? 'bg-brand-primary-accent/50 cursor-not-allowed' 
                : 'bg-brand-primary-accent hover:bg-brand-primary-accent/90 focus:ring-2 focus:ring-offset-2 focus:ring-brand-primary-accent'
            }`
          },
            isLoading && React.createElement(Loader2, { className: "w-5 h-5 animate-spin" }),
            isLoading ? t.auth.register.creatingAccount : t.auth.register.createAccount
          )
        ),

        // Switch to login
        React.createElement("div", { className: "text-center mt-6 pt-6 border-t border-gray-200" },
          React.createElement("p", { className: "text-sm text-brand-muted-text" },
            t.auth.register.hasAccount, " ",
            React.createElement("button", {
              onClick: onSwitchToLogin,
              className: "font-medium text-brand-primary-accent hover:text-brand-primary-accent/80 underline focus:outline-none"
            }, t.auth.register.signInLink)
          )
        )
      )
    )
  );
};

export default Register;