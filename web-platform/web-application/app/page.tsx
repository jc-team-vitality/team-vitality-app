'use client';
import { LoginButton } from '../src/components/LoginButton';

export default function LoginPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-slate-100 p-4">
      <div className="w-full max-w-md p-10 sm:p-12 bg-white rounded-xl shadow-2xl space-y-8">
        <div className="text-center">
          <h1 className="text-4xl font-bold text-slate-800 tracking-tight mb-2 select-none">
            TeamVitality
          </h1>
          <p className="text-lg text-slate-600 mb-2">
            Your intelligent partner for a healthier, more vital life.
          </p>
        </div>
        <div>
          <LoginButton
            providerName="google"
            displayText="Sign in with Google"
            className="w-full flex items-center justify-center py-3 px-5 bg-blue-600 text-white text-md font-semibold rounded-lg shadow hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-colors duration-150"
          />
        </div>
      </div>
    </main>
  );
}
