import express from "express";
import { login, register, reVerify, verify } from "../controllers/userController.js";
import { isAuthenticated } from "../middleware/isAuthenticated.js";


const router = express.Router();
router.post("/register", register)  
router.post("/verify", verify)  
router.post("/reVerify", reVerify)  
router.post("/login", login)  
router.post("/logout",isAuthenticated , logout)  

export default router;