// eCyber/src/lib/apiClient.ts
// This file now re-exports the centralized apiClient from services/api.ts
// to ensure a single instance is used throughout the application.

// Adjust the import path if necessary. Assuming '@/' resolves to 'eCyber/src/'
import { apiClient } from '@/services/api';

export default apiClient;
