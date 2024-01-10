import express, { Express, Request, Response } from "express";
//import Users from "./Models/Users";
const Users = require('./Models/Users');
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
//import express_validator, { body, validationResult } from "express-validator";
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
    return done(null,{email: jwt_payload.email});
}))



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
    if (req.user) {
        res.status(200).json( req.user );
    } else {
        res.status(401).send('Unauthorized');
    }
});

app.post("/api/user/register/", async (req: Request,res:Response) => {
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
            res.status(201).send('User created');
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

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
})
