import './App.css';
import Login from './pages/login/Login.jsx'
import Register from './pages/register/Register.jsx'
import HomePage from './pages/homePage/HomePage.jsx';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom'
import axios from 'axios'
import { useEffect, useState, useCallback } from 'react';
import { UserContext } from './context/UserContext';

// Move these outside the App component
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
        const res = await axios.get('http://localhost:3000/api/auth/check-user', { withCredentials: true });
        setUser(res.data.user);
      } catch (err) {
        setUser(null);
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