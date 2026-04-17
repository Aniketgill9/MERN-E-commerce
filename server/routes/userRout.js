import express from "express";
import { allUsers, changePassword, forgotPassword, login, logout, register, reVerify, verify, verifyOTP } from "../controllers/userController.js";
import { isAuthenticated } from "../middleware/isAuthenticated.js";


const router = express.Router();
router.post("/register", register)  
router.post("/verify", verify)  
router.post("/reVerify", reVerify)  
router.post("/login", login)  
router.post("/logout",isAuthenticated ,logout)  
router.post("/forgotPassword" ,forgotPassword)  
router.post("/verifyOTP/:email", verifyOTP)
router.post("/changePassword/:email", changePassword) 
router.get("/all-users/", allUsers) 

export default router;