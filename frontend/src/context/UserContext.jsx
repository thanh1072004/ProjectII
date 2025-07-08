import React, { createContext, useState } from 'react';

export const UserContext = createContext({
  user: null,
  setUser: () => {},
  privateKey: null,
  setPrivateKey: () => {},
});

export const UserProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [privateKey, setPrivateKey] = useState(null);

    return (
        <UserContext.Provider value={{ user, setUser, privateKey, setPrivateKey }}>
            {children}
        </UserContext.Provider>
    );
};