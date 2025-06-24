import { createContext } from 'react';

export const UserContext = createContext({
  user: null,
  setUser: () => {},
  privateKey: null,
  setPrivateKey: () => {},
});
