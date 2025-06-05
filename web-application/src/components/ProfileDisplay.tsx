// src/components/ProfileDisplay.tsx
'use client';
import { useAuth } from '../contexts/AuthContext';

export const ProfileDisplay = () => {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <p>Loading authentication status...</p>;
  }

  if (!isAuthenticated || !user) {
    return <p>You are not logged in.</p>;
  }

  return (
    <div>
      <p>Welcome, {user.email}!</p>
      <p>User ID: {user.userId}</p>
      <p>Roles: {user.roles.join(', ')}</p>
    </div>
  );
};
