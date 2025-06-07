// eCyber/src/services/api.ts
import axios from 'axios';

// Define the base URL for the API. Adjust if your backend is served elsewhere.
// Assuming the backend is served on the same domain, prefixed with /api/v1
const API_BASE_URL = 'https://ecyber-backend.onrender.com/api/v1'; 

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Function to get the auth token (e.g., from localStorage or context)
export const getAuthToken = (): string | null => {
  return localStorage.getItem('authToken'); // Example: store token in localStorage
};

// Add a request interceptor to include the auth token in headers
apiClient.interceptors.request.use(
  (config) => {
    const token = getAuthToken();
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// --- Authentication Endpoints ---

interface LoginResponse {
  access_token: string;
  token_type: string;
  is_2fa_required?: boolean;
  user_id?: number;
}

export const loginUser = async (credentials: any): Promise<LoginResponse> => {
  const response = await apiClient.post<LoginResponse>('/auth/login', new URLSearchParams(credentials), { // Changed endpoint
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' } // FastAPI's OAuth2PasswordRequestForm expects form data
  });
  return response.data;
};

interface Verify2FAResponse {
  access_token: string;
  token_type: string;
}

export const verifyTwoFactorLogin = async (code: string, tempToken: string): Promise<Verify2FAResponse> => {
  const response = await apiClient.post<Verify2FAResponse>('/auth/verify-2fa', { code }, {
    headers: { Authorization: `Bearer ${tempToken}` }
  });
  return response.data;
};

// This existing function is for setting up 2FA for an already authenticated user, not for login flow.
// It might need path adjustment if backend paths for 2FA setup changed, but that's outside this subtask.
export const verifyTwoFactor = async (data: { userId: number; code: string }) => {
  // The backend endpoint expects { user_id: int, code: str } in the body
  // This path was /auth/login/verify-2fa, which is now used by verifyTwoFactorLogin.
  // Assuming the backend path for enabling 2FA for an already logged-in user is something like /auth/2fa/verify or /auth/2fa/enable
  // For now, let's comment it out to avoid confusion, or assume it needs a different path.
  // const response = await apiClient.post('/auth/login/verify-2fa', { user_id: data.userId, code: data.code });
  // return response.data; 
  console.warn("verifyTwoFactor function in api.ts might need path adjustment for non-login 2FA verification.");
  return Promise.reject("Path for verifyTwoFactor (non-login) needs review.");
};

export const registerUser = async (userData: any) => {
  const response = await apiClient.post('/auth/register', userData);
  return response.data; // Expected: UserSchema
};

export const requestPasswordReset = async (emailData: { email: string }) => {
  const response = await apiClient.post('/auth/password-recovery/request-token', emailData);
  return response.data; // Expected: { message: string }
};

export const resetPasswordWithToken = async (resetData: { token: string; new_password: string }) => {
  const response = await apiClient.post('/auth/password-recovery/reset-password', resetData);
  return response.data; // Expected: { message: string }
};

// --- 2FA Management Endpoints (Authenticated) ---

export const generate2FASecret = async () => {
  const response = await apiClient.post('/auth/2fa/generate-secret');
  return response.data; // Expected: { secret: string, qr_code_uri: string }
};

export const enable2FA = async (twoFactorCode: { code: string }) => {
  const response = await apiClient.post('/auth/2fa/enable', twoFactorCode);
  return response.data; // Expected: { message: string }
};

export const disable2FA = async () => {
  const response = await apiClient.post('/auth/2fa/disable');
  return response.data; // Expected: { message: string }
};

// --- User Endpoints (Authenticated) ---

// Assuming User interface/type is defined elsewhere or here for now
interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
}

export const getUsers = async (skip: number = 0, limit: number = 10): Promise<User[]> => {
  // The backend endpoint for users was /users_v1 to avoid conflict
  const response = await apiClient.get('/users_v1/', { params: { skip, limit } });
  return response.data; // Expected: List[UserSchema]
};

// --- Change Password Endpoint (Authenticated) ---
// This endpoint was not explicitly created in the backend plan.
// Assuming an endpoint like /auth/change-password for now.
// This would require current_password, new_password.
export const changePassword = async (passwordData: any) => {
  // Let's assume a new endpoint /auth/users/me/change-password or similar for current user
  // For now, creating a placeholder. This needs to be defined in the backend.
  // If using a generic user update, it might be: apiClient.patch('/users/me', { password_data_here })
  // For this example, let's define it as if it's a specific endpoint:
  const response = await apiClient.post('/auth/change-password', passwordData); // Replace with actual endpoint
  return response.data; // Expected: { message: string }
};


// --- Helper function to store token (example) ---
export const storeAuthToken = (token: string) => {
  localStorage.setItem('authToken', token);
};

export const removeAuthToken = () => {
  localStorage.removeItem('authToken');
};

// You might also want a function to get the current user's profile
// export const getCurrentUserProfile = async () => {
//   const response = await apiClient.get('/users/me'); // Assuming a /users/me endpoint
//   return response.data;
// };
