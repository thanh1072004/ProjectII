import React, { useEffect, useState } from 'react';
import axios from 'axios';
import './CompanyMembers.css';

export default function CompanyMembers() {
  const [members, setMembers] = useState([]);

  useEffect(() => {
    const fetchMembers = async () => {
      try {
        const res = await axios.get('http://localhost:3000/api/company-members', { withCredentials: true });
        setMembers(res.data.users);
      } catch (err) {
        setMembers([]);
      }
    };
    fetchMembers();
  }, []);

  return (
    <div className="company-container">
      <h2 className="company-title">MEMBER OF YOUR COMPANY</h2>
      <table className="company-table">
        <thead>
          <tr>
            <th>Order</th>
            <th>Email</th>
            <th>Position</th>
          </tr>
        </thead>
        <tbody>
          {members.length > 0 ? (
            members.map((user, idx) => (
              <tr key={user._id}>
                <td>{idx + 1}</td>
                <td>{user.email}</td>
                <td>{user.role}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={3} style={{ textAlign: 'center', color: '#888' }}>No members found.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
