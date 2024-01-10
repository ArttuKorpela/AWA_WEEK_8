//TODO: Figure out why only plain JS seems to work.

/*
import mongoose, { Schema, Model, connect } from 'mongoose';

interface IUser {
    email:string;
    password:string;
}


const userSchema = new Schema<IUser>({
    email: {
        type: String, require: true
    },
    password:{
        type: String, require: true
    }
});


const Users = mongoose.model<IUser>("Users",userSchema);


export default Users;
*/

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
  },
  password: {
    type: String,
  }
});

const Users = mongoose.model('Users', userSchema);

module.exports = Users;