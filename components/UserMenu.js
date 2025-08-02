import React, { useState, useRef, useEffect } from 'react';
import { User, LogOut, ChevronDown, Settings } from 'lucide-react';
import { useAuth } from '../auth/AuthContext.js';

const UserMenu = ({ translations }) => {
  const { user, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);

  const t = translations;

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  // Close menu on escape key
  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [isOpen]);

  const handleLogout = async () => {
    setIsOpen(false);
    await logout();
  };

  // Get user initials for avatar
  const getUserInitials = (user) => {
    if (!user) return 'U';
    
    // If firstName is available, use first letter of firstName + first letter of last name (email prefix)
    if (user.firstName) {
      const firstNameInitial = user.firstName[0].toUpperCase();
      if (user.email) {
        const emailPrefix = user.email.split('@')[0];
        const emailParts = emailPrefix.split('.');
        // If email has multiple parts, use second part's first letter as last name initial
        if (emailParts.length >= 2) {
          return firstNameInitial + emailParts[1][0].toUpperCase();
        }
        // Otherwise use second character of first name or email prefix
        const secondInitial = user.firstName.length > 1 ? user.firstName[1].toUpperCase() : emailPrefix[0].toUpperCase();
        return firstNameInitial + secondInitial;
      }
      return firstNameInitial + (user.firstName.length > 1 ? user.firstName[1].toUpperCase() : 'U');
    }
    
    // Fallback to email-based initials
    if (user.email) {
      const parts = user.email.split('@')[0].split('.');
      if (parts.length >= 2) {
        return (parts[0][0] + parts[1][0]).toUpperCase();
      }
      return user.email[0].toUpperCase();
    }
    
    return 'U';
  };

  return React.createElement("div", { className: "relative", ref: menuRef },
    // Menu trigger button
    React.createElement("button", {
      onClick: () => setIsOpen(!isOpen),
      className: "flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-brand-primary-accent/10 text-brand-text transition-colors focus:outline-none focus:ring-2 focus:ring-brand-primary-accent",
      "aria-expanded": isOpen,
      "aria-haspopup": true
    },
      // User avatar
      React.createElement("div", { className: "w-8 h-8 bg-brand-primary-accent text-white rounded-full flex items-center justify-center text-sm font-medium" },
        getUserInitials(user)
      ),
      // User display name (hidden on mobile)
      React.createElement("span", { className: "hidden sm:block text-sm font-medium text-brand-text max-w-32 truncate" },
        user?.firstName || user?.email || t.auth.user.unknown
      ),
      // Dropdown arrow
      React.createElement(ChevronDown, { 
        className: `w-4 h-4 text-brand-muted-text transition-transform ${isOpen ? 'rotate-180' : ''}` 
      })
    ),

    // Dropdown menu
    isOpen && React.createElement("div", {
      className: "absolute right-0 mt-2 w-56 bg-brand-card-bg rounded-lg shadow-brand-lg border border-gray-200 py-1 z-50",
      role: "menu",
      "aria-orientation": "vertical"
    },
      // User info section
      React.createElement("div", { className: "px-4 py-3 border-b border-gray-200" },
        React.createElement("p", { className: "text-sm font-medium text-brand-text" }, t.auth.user.signedInAs),
        React.createElement("p", { className: "text-sm text-brand-text font-medium truncate" }, user?.firstName || user?.email?.split('@')[0] || t.auth.user.unknown),
        user?.firstName && React.createElement("p", { className: "text-xs text-brand-muted-text truncate" }, user?.email)
      ),

      // Menu items
      React.createElement("div", { className: "py-1" },
        // Profile/Settings option (for future use)
        React.createElement("button", {
          className: "w-full px-4 py-2 text-left text-sm text-brand-text hover:bg-brand-bg/50 flex items-center gap-3",
          role: "menuitem",
          onClick: () => {
            setIsOpen(false);
            // TODO: Navigate to profile/settings
          }
        },
          React.createElement(Settings, { className: "w-4 h-4 text-brand-muted-text" }),
          t.auth.user.settings
        ),

        // Logout option
        React.createElement("button", {
          className: "w-full px-4 py-2 text-left text-sm text-brand-error hover:bg-brand-error/5 flex items-center gap-3 border-t border-gray-200 mt-1 pt-3",
          role: "menuitem",
          onClick: handleLogout
        },
          React.createElement(LogOut, { className: "w-4 h-4" }),
          t.auth.user.signOut
        )
      )
    )
  );
};

export default UserMenu;