import React, { useState } from 'react';
import './RoleToggle.css';

const RoleToggle = ({ onToggle }) => {
  const [role, setRole] = useState('employee');

  const handleToggle = (newRole) => {
    setRole(newRole);
    onToggle(newRole); // Gửi giá trị lên App.jsx
  };

  return (
    <div className="role-toggle">
      <div
        className={`role-option ${role === 'employee' ? 'selected' : ''}`}
        onClick={() => handleToggle('employee')}
      >
        Employee
      </div>
      <div
        className={`role-option ${role === 'manager' ? 'selected' : ''}`}
        onClick={() => handleToggle('manager')}
      >
        Manager
      </div>
    </div>
  );
};

export default RoleToggle;
