'use client';
import { LoginButton } from '../src/components/LoginButton';
import { LogoutButton } from '../src/components/LogoutButton';
import { ProfileDisplay } from '../src/components/ProfileDisplay';

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24">
      <h1 className="text-4xl font-bold mb-4">
        Hello World from TeamVitality Web Application (Next.js)
      </h1>
      <ProfileDisplay />
      <LoginButton providerName="google" displayText="Sign in with Google" />
      {/* Add other IdP login buttons as needed */}
      <LogoutButton />
    </main>
  )
}
