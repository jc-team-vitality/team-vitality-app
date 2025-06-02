// src/components/LoginButton.tsx
'use client';
import { useAuth } from '../contexts/AuthContext';

interface LoginButtonProps {
  providerName: string;
  displayText?: string;
}

export const LoginButton = ({ providerName, displayText }: LoginButtonProps) => {
  const { login, isAuthenticated, isLoading } = useAuth();

  if (isLoading || isAuthenticated) {
    return null;
  }

  return (
    <button onClick={() => login(providerName)}>
      {displayText || `Login with ${providerName.charAt(0).toUpperCase() + providerName.slice(1)}`}
    </button>
  );
};
