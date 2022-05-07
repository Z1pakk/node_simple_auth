const jwt = require("jsonwebtoken");
const {secret} = require("../config");

module.exports = function(roles) {
    return function(req, res, next) {
        if (req.method == "OPTIONS") {
            next();
        }

        try{
            const token = req.headers.authorization.split(' ')[1];
            if (!token) {
                return res.status(403).json({message: "User is not authenticated"});
            }
            const {roles: userRoles} = jwt.verify(token, secret);
            let hasRole = userRoles.some(r => roles.includes(r));
            if (!hasRole) {
                return res.status(403).json({message: "You don't have access"});
            }
            next();
        } catch (e) {
            console.log(e)
            return res.status(403).json({message: "User is not authenticated"});
        }
    }
}
