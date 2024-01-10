import express, { Express, Request, Response } from "express";
//import Users from "./Models/Users";
const Users = require('./Models/Users');
import Todos from "./Models/Todo";
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { body, validationResult } from 'express-validator';
import dotenv from 'dotenv'; 
import * as jwt from 'jsonwebtoken';
dotenv.config();
const secret_key = process.env.SECRET!;
if (!secret_key) {
    console.error("Fatal Error: SECRET is not set in .env file.");
    process.exit(1); 
}
//console.log(secret_key);
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import passport from 'passport';


const passport_options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET
}

passport.use(new JwtStrategy(passport_options, (jwt_payload, done) => {
    return done(null,{data: jwt_payload});
}))

interface UserPayload {
    data: {
      id: string;
      email: string;
      iat: number;
      exp: number;
    };
  };

  interface todoPayload {
    user: string;
    items:string[];
  };


const mongoDB: string = "mongodb://127.0.0.1:27017/testdb";
mongoose.connect(mongoDB);
mongoose.Promise = global.Promise;
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.on('open', () => {
    console.log('Connected to MongoDB');
});

async function hashPassword(password: string) {
    const saltRounds: number = 10;
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        return hashedPassword;
    } catch (error) {
        console.error(error);
    }
}


const app: Express = express();
const port: number = 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));




app.get("/hello", (req: Request, res: Response) => {
    res.send("Hello world!")
})

app.get('/api/private', passport.authenticate('jwt', { session: false }), (req, res) => {
    const user = req.user as UserPayload;
    if (user) {
        res.status(200).json( {email: user.data.email});
    } else {
        res.status(401).send('Unauthorized');
    }
});


app.post("/api/user/register/",
    body("email")
        .isEmail()
        .withMessage("Invalid email address"),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/[a-z]/)
        .withMessage('Password must contain at least one lowercase letter')
        .matches(/[A-Z]/)
        .withMessage('Password must contain at least one uppercase letter')
        .matches(/[0-9]/)
        .withMessage('Password must contain at least one number')
        .matches(/[~`!@#$%^&*()-_+={}[\]|\\:;"'<>,./?]/)
        .withMessage('Password must contain at least one symbol (~`!@#$%^&*()-_+={}[]|\\;:"<>,./?)'),
    
    async (req: Request,res:Response) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const email: string = req.body.email;
        const password_plain: string = req.body.password;

        try {
            const existingUser = await Users.findOne({ email: email });
            if (existingUser) {
                return res.status(403).send("Email taken")
            }else{
                const hashed_password = await hashPassword(password_plain);
                const newUser = new Users({
                    email: email,
                    password: hashed_password
                })
                await newUser.save();
                res.status(200).send('User created');
            }
        } catch (error) {
            console.error(error);
            res.status(500).send('Error processing request');
        }
});

app.post("/api/user/login/", async (req: Request,res:Response) => {
    const email: string = req.body.email;
    const password: string = req.body.password;

    try {
        const existing_user = await Users.findOne({email: email});
        if (existing_user) {
            bcrypt.compare(password, existing_user.password, (err, match) => {
                if (err) {throw err}
                if (match) {
                    
                    const jswToken = {
                        id: existing_user._id,
                        email: existing_user.email,
                    };
                    
                    jwt.sign(jswToken, String(secret_key), {
                        expiresIn: 120
                    }, (err, token) => {
                        if (err) {throw err}
                        else {
                            res.json({
                                success: true,
                                token: token
                            });
                        };
                    });

                } else {
                    res.send("No match");
                }
            }) 
        } else {
            return res.send("No user with this email");
        }
    } catch(err) {
        return res.status(403).send("Error in login");
    }
    
})


app.post("/api/todos/", passport.authenticate('jwt', { session: false }),
    async (req: Request, res: Response) => {
        try {
            const user = req.user as UserPayload;
            const userId = user.data.id;
            const newItems: string[] = req.body.items;

            let existingUser = await Todos.findOne({ user: userId });
            if (existingUser) {
                existingUser.item.push(...newItems); 
                await existingUser.save();
            } else {
                const newUser = new Todos({ user: userId, item: newItems });
                await newUser.save();
            }
            res.status(200).send("Success");
        } catch (err) {
            res.status(500).send('Error processing your request');
        }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
})
