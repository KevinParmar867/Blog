import axios from "axios";
import { createContext, useEffect, useState } from "react";

export const AuthContext = createContext();

export const AuthContexProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(
    JSON.parse(localStorage.getItem("user")) || null
  );

  const login = async (inputs) => {
    const res = await axios.post("/auth/login", inputs);
    setCurrentUser(res.data);
  };

  const register = async (inputs) => {
    try {
      const response = await axios.post("/auth/register", inputs);
      // After a successful registration, set the user in the context
      setCurrentUser(response.data);
    } catch (err) {
      // Handle registration errors
      console.error(err);
    }
  };

  const logout = async () => {
    await axios.post("/auth/logout");
    setCurrentUser(null);
    // Clear user data from localStorage when logging out
    localStorage.removeItem("user");
  };

  useEffect(() => {
    localStorage.setItem("user", JSON.stringify(currentUser));
  }, [currentUser]);

  return (
    <AuthContext.Provider
      value={{ currentUser, login, logout, register }}
    >
      {children}
    </AuthContext.Provider>
  );
};

