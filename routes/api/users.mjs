import express from 'express';
import bcrypt from 'bcrypjs';
import jwt from 'jsonwebtoken';
import {check, validationResult} from 'express-validator';
import User from '../../models/User.mjs'

const router = express.Router();

// @route:   GET api/users
// @desc:    Test route
// @access:  Public
// router.get('/', (req, res) => res.send('User Route'));

//@route: POST api/users
//@desc: Create User
//@access: Public
router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({min: 6})
], async(req, res)=>{
    //check if any validation errors
    const errors = validationResult(req)

    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    //destructure our req
    const {name, email ,password} = req.body

    try {
        //check if user already exists
        let user = await User.findOne({email});
        //if they exist, respond with error
        if(user) {
            return res.status(400).json({errors: [{msg: 'User Already Exists'}]});
        }
        //create a user
        user = new User({
            name,
            email,
            password,
        })

        //encrypt password (run through a "salt" why is it called that? 10 rounds recommended?)
        const salt = await bcrypt.genSalt(10)

        user.password = await bcrypt.hash(password, salt)

        await user.save()

        //creating payload (data for the front end) for JWT
        const payload = {
            user: {
                id: user.id,
                name: user.name
            }
        }
        //creating a JWT, signing it, and, if there are no errors, sending token to the front end
        jwt.sign(
            payload,
            process.env.jwtSecret,
            {expiresIn: 3600 },
            (err, token) => {
                if(err) throw err;

                res.json({ token });
            }
        );

    } catch (err) {
        console.error(err)
        res.status(500).json({msg: "Server Error"})
    }
})

export default router;
