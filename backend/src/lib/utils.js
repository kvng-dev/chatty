import jwt from "jsonwebtoken";
export const createToken = (userId, res) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
  res.cookie("jwt", token, {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "developmment",
  });

  return token;
};
