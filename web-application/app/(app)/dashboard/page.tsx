'use client';
import React from 'react';
import { useAuth } from '../../../src/contexts/AuthContext';

export default function DashboardPage() {
  const { user } = useAuth();

  return (
    <div>
      <h1 className="text-2xl font-semibold text-gray-700">Dashboard</h1>
      <p className="mt-2 text-gray-600">
        Welcome to your TeamVitality dashboard, {user?.email}!
      </p>
      <div className="mt-4 p-4 bg-white shadow rounded-lg">
        <h2 className="text-xl">Your Information:</h2>
        <p>User ID: {user?.userId}</p>
        <p>Roles: {user?.roles?.join(', ')}</p>
      </div>
      {/* This is where other dashboard components or content would go.
        The chat interface would typically be a major part of this or a separate '/chat' page
        within this (app) layout group.
      */}
    </div>
  );
}
