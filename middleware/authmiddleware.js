const jwt = require("jsonwebtoken");
const SECRET_KEY =
    "8be165cb3e1816b9370d87866649742a7ee214b06bb26dd47fe355a04af50d03"; // Should match the one in authController

function authenticateToken(req, res, next) {
    // Ensure req.cookies exists
    if (!req.cookies) {
        return res
            .status(401)
            .json({ message: "Access denied. No cookies found." });
    }

    const token = req.cookies.token; // Read token from HTTP-only cookie

    if (!token) {
        return res
            .status(401)
            .json({ message: "Access denied. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded; // Attach decoded token info to the request
        next();
    } catch (error) {
        return res.status(403).json({ message: "Invalid or expired token." });
    }
}

module.exports = authenticateToken;