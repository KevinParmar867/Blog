import { db } from "../db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = (req, res) => {
  // CHECK EXISTING USER
  const q = "SELECT * FROM user WHERE email = ? OR name = ?";

  db.query(q, [req.body.email, req.body.name], (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length) return res.status(409).json("User already exists!");

    // Hash the password and create a user
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);

    const insertQuery = "INSERT INTO user(`name`, `email`, `password`) VALUES (?, ?, ?)";
    const values = [req.body.name, req.body.email, hash];

    db.query(insertQuery, values, (err, result) => {
      if (err) return res.status(500).json(err);

      // Generate a JWT token for the newly registered user
      const token = jwt.sign({ id: result.insertId }, "jwtKey");

      // Retrieve user data from the database
      const getUserQuery = "SELECT * FROM user WHERE id = ?";
      db.query(getUserQuery, [result.insertId], (err, userData) => {
        if (err) return res.status(500).json(err);

        // Exclude password from the user data
        const { password, ...other } = userData[0];

        return res.cookie("access_token", token, {
          httpOnly: true,
        }).status(200).json(other);
      });
    });
  });
};


export const login = (req, res) => {
  //CHECK USER

  const q = "SELECT * FROM user WHERE email = ?";

  db.query(q, [req.body.email], (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length === 0) return res.status(404).json("User not found!");

    //Check password
    const isPasswordCorrect = bcrypt.compareSync(
      req.body.password,
      data[0].password
    );

    if (!isPasswordCorrect)
      return res.status(400).json("Wrong username or password!");

    const token = jwt.sign({ id: data[0].id }, "jwtKey");
    const { password, ...other } = data[0];

    res
      .cookie("access_token", token, {
        httpOnly: true,
      })
      .status(200)
      .json(other);
  });
};

export const logout = (req, res) => {
  res.clearCookie("access_token",{
    sameSite:"none",
    secure:true
  }).status(200).json("User has been logged out.")
};
