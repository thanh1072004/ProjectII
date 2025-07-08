import './App.css';
import Login from './pages/login/Login.jsx';
import Register from './pages/register/Register.jsx';
import HomePage from './pages/homePage/HomePage.jsx';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import axios from 'axios';
import { useEffect, useState } from 'react';
import { UserContext } from './context/UserContext';

const ProtectedRoutes = ({ user, loading }) => {
    if (loading) return <div>Loading...</div>;
    return user ? <Outlet /> : <Navigate to='/login' replace />;
};

const AuthenRoutes = ({ user, loading }) => {
    if (loading) return <div>Loading...</div>;
    return !user ? <Outlet /> : <Navigate to='/dashboard' replace />;
};

function App() {
    const [user, setUser] = useState(null);
    const [privateKey, setPrivateKey] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchUser = async () => {
            try {
                const token = sessionStorage.getItem('accessToken');
                if (!token) {
                    console.log('No access token found in sessionStorage, redirecting to login');
                    setLoading(false);
                    return;
                }

                console.log('Fetching user with token:', token.substring(0, 20) + '...');
                const res = await axios.get(`${import.meta.env.VITE_API_URL}/auth/check-user`, {
                    withCredentials: true // Gửi cookie accessToken
                });
                console.log('Fetched user:', res.data.user);
                setUser(res.data.user);
                setPrivateKey(sessionStorage.getItem('privateKey'));
            } catch (err) {
                console.error('Failed to fetch user:', err.message);
                if (err.response) {
                    console.error('Response status:', err.response.status);
                    console.error('Response data:', err.response.data);
                }
                setUser(null);
                setPrivateKey(null);
                sessionStorage.removeItem('accessToken');
                sessionStorage.removeItem('privateKey');
                console.log('Cleared sessionStorage due to fetch user failure');
            } finally {
                setLoading(false);
            }
        };
        fetchUser();
    }, []);

    return (
        <UserContext.Provider value={{ user, setUser, privateKey, setPrivateKey }}>
            <Routes>
                <Route path='/' element={<Navigate to='/login' replace />} />
                <Route element={<AuthenRoutes user={user} loading={loading} />}>
                    <Route path='/login' element={<Login />} />
                    <Route path='/register' element={<Register />} />
                </Route>
                <Route element={<ProtectedRoutes user={user} loading={loading} />}>
                    <Route path='/dashboard' element={<HomePage />} />
                </Route>
            </Routes>
        </UserContext.Provider>
    );
}

export default App;