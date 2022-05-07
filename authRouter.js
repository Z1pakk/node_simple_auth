const Router = require('express');
const router = new Router();
const controller = require('./authController');
const {check} = require("express-validator");
const authMiddleware = require('./middlewares/authMiddleware')
const roleMiddleware = require('./middlewares/roleMiddleware')

router.post('/registration', [
    check("username", "Username is required").notEmpty(),
    check("password", "Password must be longer than 4 symbols and shorter than 10 symbols.").isLength({min: 4, max: 10}),
], controller.registration);
router.post('/login', controller.login);
router.get('/users', roleMiddleware(['User', 'Admin']), controller.getUsers)

module.exports = router;
