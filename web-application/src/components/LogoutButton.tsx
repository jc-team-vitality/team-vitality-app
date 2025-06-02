// src/components/LogoutButton.tsx
'use client';
import { useAuth } from '../contexts/AuthContext';

export const LogoutButton = () => {
  const { logout, isAuthenticated, isLoading } = useAuth();

  if (isLoading || !isAuthenticated) {
    return null;
  }

  return <button onClick={logout}>Logout</button>;
};
