import { apiFetch } from './client';
import { loadApiSettings } from './settings';

export interface BasicUser {
    username: string;
    role: string;
}

export async function getBasicUsers(): Promise<BasicUser[]> {
    const s = loadApiSettings();
    return apiFetch<BasicUser[]>('/api/auth/basic/users', { baseUrl: s.metricsBaseUrl });
}

export async function putBasicUser(username: string, role: string, password?: string): Promise<void> {
    const s = loadApiSettings();
    return apiFetch<void>('/api/auth/basic/users', {
        method: 'POST',
        baseUrl: s.metricsBaseUrl,
        body: { username, role, password }
    });
}

export async function deleteBasicUser(username: string): Promise<void> {
    const s = loadApiSettings();
    return apiFetch<void>('/api/auth/basic/users', {
        method: 'DELETE',
        baseUrl: s.metricsBaseUrl,
        body: { username }
    });
}
