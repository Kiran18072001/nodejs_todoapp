import { User } from "../models/user.js";
import jwt from 'jsonwebtoken';

// created because some of the routes should be accessible only after logging in the account,
// so for all the routes using authentication code is pretty hectic so to avoid this we created
// a separated function and can be used as a middleware for the other routes.

export const isAuthenticated = async(req, res, next) => {
    const { token } = req.cookies;
    console.log(token);

    if (!token) {
        res.status(404).json({
            success: false,
            message: "Login First"
        })
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded._id);
    next();
}