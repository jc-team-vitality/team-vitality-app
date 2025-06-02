// src/lib/apiClient.ts
const BFF_BASE_URL = '/api'; // Assuming BFF is proxied under /api by Firebase or served on same domain

interface ApiClientOptions extends RequestInit {
  // Add any custom options if needed
}

async function apiClient<T = any>(
  endpoint: string,
  options?: ApiClientOptions,
): Promise<T> {
  const { body, ...customConfig } = options || {};
  const headers: HeadersInit = { 'Content-Type': 'application/json' };
  // Add other default headers if necessary, e.g., CSRF token if not using cookies alone

  const config: RequestInit = {
    method: body ? 'POST' : 'GET',
    headers: {
      ...headers,
      ...customConfig.headers,
    },
    ...customConfig,
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(`${BFF_BASE_URL}${endpoint}`, config);

    if (!response.ok) {
      // Attempt to parse error, but fallback if not JSON
      let errorData;
      try {
        errorData = await response.json();
      } catch (e) {
        errorData = { message: response.statusText };
      }
      // Throw an error object that can be caught and inspected
      const error = new Error(errorData.message || 'API request failed') as any;
      error.status = response.status;
      error.data = errorData;
      throw error;
    }
    
    // Handle cases where response might be empty (e.g., 204 No Content for logout)
    if (response.status === 204 || response.headers.get('Content-Length') === '0') {
      return undefined as T; // Or handle as appropriate for your app
    }
    return await response.json() as T;
  } catch (error) {
    console.error('API Client Error:', error);
    throw error; // Re-throw to be caught by calling function
  }
}

export default apiClient;
