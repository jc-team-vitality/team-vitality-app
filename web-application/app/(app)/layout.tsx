'use client'; // This layout will use hooks and manage client-side concerns
import React, { ReactNode, useEffect } from 'react';
import { useAuth } from '../../src/contexts/AuthContext';
import { AppShell } from '../../src/components/layout/AppShell';
import { useRouter } from 'next/navigation';

export default function AuthenticatedAppLayout({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/'); // Redirect to home/login page if not authenticated
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading) {
    return <div>Loading application...</div>; // Or a proper loading spinner component
  }

  if (!isAuthenticated) {
    // This will typically be handled by the redirect, but as a fallback
    return <div>Redirecting to login...</div>; // Or null, as redirect should occur
  }

  return <AppShell>{children}</AppShell>;
}
