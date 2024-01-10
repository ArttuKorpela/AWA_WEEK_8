import mongoose, { Schema } from 'mongoose';

const todoSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'Users',
  },
  item: {
    type: [String],
  }
});

const Todos = mongoose.model('Todos', todoSchema);

export default Todos;