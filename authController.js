const User = require('./models/User')
const Role = require('./models/Role')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const { validationResult } = require('express-validator')
const { secret } = require('./config')

const hashRounds = 8;

const generateAccessToken = (id, roles) => {
    const payload = {
        id,
        roles
    }

    return jwt.sign(payload, secret, {expiresIn: "24h"})
}

class AuthController {
    async registration(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({message: "Registration error", errors})
            }
            const {username, password} = req.body;
            const candidate = await User.findOne({username});
            if (candidate) {
                return res.status(400).json({message: "User already exists"})
            }

            const hashPassword = await bcrypt.hash(password.toString(), hashRounds);

            const userRole = await Role.findOne({value: 'Admin'});
            const user = new User({username, password: hashPassword, roles: [userRole.value]});
            await user.save();
            return res.json({message: "User has been registered"});

        } catch(e) {
            console.log(e)
            res.status(400).json({message: "Registration error" + e.message})
        }
    }

    async login(req, res) {
        try {
            const {username, password} = req.body;
            const user = await User.findOne({username});
            if (!user) {
                return res.status(400).json({message: `User ${username} not found`})
            }

            const validPassword = bcrypt.compareSync(password, user.password);
            if (!validPassword) {
                return res.status(400).json({message: `Password is incorrect`})
            }

            const token = generateAccessToken(user._id, user.roles);
            return res.json({token});

        } catch(e) {
            console.log(e)
            res.status(400).json({message: "Login error"})
        }
    }

    async getUsers(req, res) {
        try {
            // Init default roles
            // const userRole = new Role();
            // const adminRole = new Role({value: 'Admin'})
            // await userRole.save();
            // await adminRole.save();

            const users = await User.find();
            res.json(users);
        } catch(e) {
            console.log(e)
            res.status(400).json({message: "Users error"})
        }
    }
}

module.exports = new AuthController();
