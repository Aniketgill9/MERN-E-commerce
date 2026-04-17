import express from 'express';
import dotenv from 'dotenv';
import connectDB from './database/db.js';
import userRoute from "./routes/userRout.js";


dotenv.config();



const app = express();

const PORT = process.env.PORT || 5000;

app.use(express.json());

app.use("/api/users", userRoute);

// http://localhost:5000/api/users/register


app.listen(PORT, () => {
    connectDB();
  console.log(`Server is running on port ${PORT}`);
});