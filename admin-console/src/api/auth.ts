import { apiFetch, controlClient } from './client';

export interface BasicUser {
    username: string;
    role: string;
}

export async function getBasicUsers(): Promise<BasicUser[]> {
    const { baseUrl, token } = controlClient();
    return apiFetch<BasicUser[]>('/api/auth/basic/users', { baseUrl, token });
}

export async function putBasicUser(username: string, role: string, password?: string): Promise<void> {
    const { baseUrl, token } = controlClient();
    return apiFetch<void>('/api/auth/basic/users', {
        method: 'POST',
        baseUrl,
        token,
        body: { username, role, password }
    });
}

export async function deleteBasicUser(username: string): Promise<void> {
    const { baseUrl, token } = controlClient();
    return apiFetch<void>('/api/auth/basic/users', {
        method: 'DELETE',
        baseUrl,
        token,
        body: { username }
    });
}
