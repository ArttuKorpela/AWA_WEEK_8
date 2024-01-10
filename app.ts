import express, { Express, Request, Response } from "express";
//import Users from "./Models/Users";
const Users = require('./Models/Users');
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

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
    
    

})

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
})
