import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import { sendCookie } from "../utils/features.js";
import ErrorHandler from "../middlewares/error.js";

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    let user = await User.findOne({email}).select("+password")
    // by default the password in user.js(Schema) is given false,
    // so to access it we need to use select and inside it we need to add("+password")
  
    if(!user) return next(new ErrorHandler("Invalid Email or Password", 400))
    // match the password
    const isMatch = await bcrypt.compare(password, user.password);
  
    if(!isMatch) return next(new ErrorHandler("Invalid email or password"), 400)
  
    sendCookie(user, res, `Welcome Back, ${user.name}`, 200);
  } catch (error) {
    next(error);
  }
};

export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
  
    // if there exists an user, return the error message
    if(user) return next(new ErrorHandler("User Already Exists", 400))
  
    // else create a new account
    const hashedPassword = await bcrypt.hash(password, 10);
    user = await User.create({
      name,
      email,
      password: hashedPassword
    })
  
    sendCookie(user, res, "Account Created Successfully.", 201);
  } catch (error) {
    next(error)
  }
};

export const getMyProfile = (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user
  })
}

export const logout = (req, res) => {
  res.status(200).cookie("token", "", {
    expires: new Date(Date.now()),
    sameSite: process.env.NODE_ENV === "Development"? "lax":"none",
    secure: process.env.NODE_ENV === "Development" ? false : true
  }).json({
    success: true,
    user: req.user
  })
}