// Typescript interface for the response from auth-service /oidc/token/exchange
// This should match the structure returned by the Python endpoint:
// { status: string, message?: string, user_info?: AppUser }

export interface OIDCTokenExchangeResponse {
  status: 'success' | 'email_conflict' | 'error';
  message?: string;
  user_info?: AppUser;
}

// This should match the AppUser model returned by auth-service
export interface AppUser {
  id: string;
  email: string;
  roles?: string[]; // Add this line for user roles
  first_name?: string;
  last_name?: string;
  created_at?: string;
  updated_at?: string;
}
