// src/components/layout/AppShell.tsx
'use client';
import React, { useState, ReactNode } from 'react';
import Link from 'next/link';
import { useAuth } from '../../contexts/AuthContext';

interface AppShellProps {
  children: ReactNode;
}

export const AppShell = ({ children }: AppShellProps) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const { user } = useAuth();

  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);

  const navItems = [
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/chat', label: 'Chat with AI Coach' },
    { href: '/my-plan', label: 'My Plan (Meals & Exercise)' },
    { href: '/tracking', label: 'Track Progress' },
    { href: '/community', label: 'Community' },
  ];

  const adminNavItems = [
    { href: '/admin/idp-configs', label: 'Manage IdPs' },
  ];

  return (
    <div className="flex h-screen bg-gray-100 text-gray-800">
      {/* Sidebar */}
      <aside 
        className={`transition-all duration-300 ease-in-out bg-gray-800 text-gray-100 flex flex-col
                    ${isSidebarOpen ? 'w-64' : 'w-20'}`}
      >
        <div className="p-4 flex items-center justify-between h-16 border-b border-gray-700">
          <span className={`font-semibold text-xl ${!isSidebarOpen && 'hidden'}`}>TeamVitality</span>
          <button 
            onClick={toggleSidebar} 
            className="p-2 rounded-md hover:bg-gray-700 focus:outline-none focus:bg-gray-700"
            aria-label="Toggle sidebar"
          >
            {isSidebarOpen ? '<' : '>'}
          </button>
        </div>
        <nav className="flex-grow p-4 space-y-2">
          {navItems.map((item) => (
            <Link key={item.label} href={item.href} legacyBehavior>
              <a className={`flex items-center p-2 space-x-3 rounded-md hover:bg-gray-700 ${!isSidebarOpen && 'justify-center'}`}>
                <span>ICON</span>
                <span className={`${!isSidebarOpen && 'hidden'}`}>{item.label}</span>
              </a>
            </Link>
          ))}
          {user?.roles?.includes('Admin') && (
            <>
              <hr className="my-4 border-gray-700" />
              <div className={`px-2 py-1 text-xs uppercase text-gray-400 ${!isSidebarOpen && 'hidden'}`}>Admin</div>
              {adminNavItems.map((item) => (
                <Link key={item.label} href={item.href} legacyBehavior>
                  <a className={`flex items-center p-2 space-x-3 rounded-md hover:bg-gray-700 ${!isSidebarOpen && 'justify-center'}`}>
                    <span>ICON</span>
                    <span className={`${!isSidebarOpen && 'hidden'}`}>{item.label}</span>
                  </a>
                </Link>
              ))}
            </>
          )}
        </nav>
        <div className={`p-4 border-t border-gray-700 ${!isSidebarOpen && 'hidden'}`}>
          {user && <p>Logged in as: {user.email}</p>}
        </div>
      </aside>
      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-gray-200 p-6">
          {children}
        </main>
      </div>
    </div>
  );
};
