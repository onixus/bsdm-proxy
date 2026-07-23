import React, { useEffect, useState } from 'react';
import { useLanguage, translations } from '../lib/i18n';
import type { BasicUser } from '../api/auth';
import { getBasicUsers, putBasicUser, deleteBasicUser } from '../api/auth';
import { Plus, Trash2, Edit2 } from 'lucide-react';

export const Users: React.FC = () => {
    const [lang] = useLanguage();
    const t = translations[lang].usersPage;
    const [users, setUsers] = useState<BasicUser[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isModalOpen, setIsModalOpen] = useState(false);
    
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        role: 'admin'
    });
    const [isEditing, setIsEditing] = useState(false);

    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            setLoading(true);
            const data = await getBasicUsers();
            setUsers(data || []);
            setError(null);
        } catch (err: any) {
            setError(err.message || 'Failed to load users');
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (username: string) => {
        if (!window.confirm(`Are you sure you want to delete ${username}?`)) return;
        try {
            await deleteBasicUser(username);
            await fetchUsers();
        } catch (err: any) {
            alert(err.message);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            await putBasicUser(
                formData.username, 
                formData.role, 
                formData.password ? formData.password : undefined
            );
            setIsModalOpen(false);
            setFormData({ username: '', password: '', role: 'admin' });
            await fetchUsers();
        } catch (err: any) {
            alert(err.message);
        }
    };

    const openCreateModal = () => {
        setIsEditing(false);
        setFormData({ username: '', password: '', role: 'admin' });
        setIsModalOpen(true);
    };

    const openEditModal = (user: BasicUser) => {
        setIsEditing(true);
        setFormData({ username: user.username, password: '', role: user.role });
        setIsModalOpen(true);
    };

    if (loading) {
        return (
            <div className="flex h-full items-center justify-center">
                <div className="text-gray-400">{t.loading}</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex h-full items-center justify-center">
                <div className="text-red-400">{error}</div>
            </div>
        );
    }

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold text-white">{t.users}</h1>
                <button
                    onClick={openCreateModal}
                    className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                    <Plus className="w-4 h-4 mr-2" />
                    {t.addUser}
                </button>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <table className="w-full text-left">
                    <thead className="bg-gray-900 border-b border-gray-700">
                        <tr>
                            <th className="px-6 py-4 text-xs font-medium text-gray-400 uppercase tracking-wider">{t.username}</th>
                            <th className="px-6 py-4 text-xs font-medium text-gray-400 uppercase tracking-wider">{t.role}</th>
                            <th className="px-6 py-4 text-xs font-medium text-gray-400 uppercase tracking-wider text-right">{t.actions}</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700">
                        {users.map((user) => (
                            <tr key={user.username} className="hover:bg-gray-750 transition-colors">
                                <td className="px-6 py-4 text-sm text-gray-300">{user.username}</td>
                                <td className="px-6 py-4 text-sm text-gray-300">
                                    <span className="px-2 py-1 bg-gray-700 rounded text-xs">
                                        {user.role}
                                    </span>
                                </td>
                                <td className="px-6 py-4 text-sm text-right space-x-2">
                                    <button
                                        onClick={() => openEditModal(user)}
                                        className="text-blue-400 hover:text-blue-300 p-1 rounded"
                                        title={t.edit}
                                    >
                                        <Edit2 className="w-4 h-4" />
                                    </button>
                                    <button
                                        onClick={() => handleDelete(user.username)}
                                        className="text-red-400 hover:text-red-300 p-1 rounded"
                                        title={t.delete}
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </td>
                            </tr>
                        ))}
                        {users.length === 0 && (
                            <tr>
                                <td colSpan={3} className="px-6 py-8 text-center text-gray-500">
                                    {t.noUsersFound}
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {isModalOpen && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                    <div className="bg-gray-800 rounded-lg max-w-md w-full border border-gray-700 shadow-xl">
                        <form onSubmit={handleSubmit} className="p-6">
                            <h2 className="text-xl font-semibold text-white mb-4">
                                {isEditing ? t.editUser : t.addUser}
                            </h2>
                            
                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                        {t.username}
                                    </label>
                                    <input
                                        type="text"
                                        value={formData.username}
                                        onChange={e => setFormData({...formData, username: e.target.value})}
                                        disabled={isEditing}
                                        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500 disabled:opacity-50"
                                        required
                                    />
                                </div>
                                
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                        {t.password} {isEditing && <span className="text-gray-500 text-xs">({t.leaveBlankToKeep})</span>}
                                    </label>
                                    <input
                                        type="password"
                                        value={formData.password}
                                        onChange={e => setFormData({...formData, password: e.target.value})}
                                        required={!isEditing}
                                        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                        {t.role}
                                    </label>
                                    <select
                                        value={formData.role}
                                        onChange={e => setFormData({...formData, role: e.target.value})}
                                        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                                    >
                                        <option value="admin">Admin</option>
                                        <option value="analyst">Analyst</option>
                                        <option value="viewer">Viewer</option>
                                    </select>
                                </div>
                            </div>

                            <div className="mt-6 flex justify-end space-x-3">
                                <button
                                    type="button"
                                    onClick={() => setIsModalOpen(false)}
                                    className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                                >
                                    {t.cancel}
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
                                >
                                    {t.save}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};
