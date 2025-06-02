// src/components/LoginButton.tsx
'use client';
import { useAuth } from '../contexts/AuthContext';

interface LoginButtonProps {
  providerName: string;
  displayText?: string;
  className?: string; // Allow passing Tailwind classes
}

export const LoginButton = ({ providerName, displayText, className }: LoginButtonProps) => {
  const { login, isAuthenticated, isLoading } = useAuth();

  if (isLoading || isAuthenticated) {
    return null;
  }

  return (
    <button
      type="button"
      onClick={() => login(providerName)}
      className={className}
    >
      {displayText || `Login with ${providerName.charAt(0).toUpperCase() + providerName.slice(1)}`}
    </button>
  );
};
