const express=require("express")
const cors=require("cors")
const ejs=require("ejs")
const app=express()
require("./config/passport")
require("dotenv").config()
const bcrypt = require('bcrypt');
const saltRounds = 10;
const passport=require("passport")
const session=require("express-session")
const MongoStore = require('connect-mongo');

require("./config/database")
const User=require("./models/user.model")
app.set("view engine","ejs")
app.use(cors())
app.use(express.urlencoded({extended:true}))
app.use(express.json());

// session-express
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl:process.env.MONGO_URL,
    collectionName:"sessions"
  })
//====================== cookie: { secure: true }
}))

app.use(passport.initialize())
app.use(passport.session())


//=======================================  base url

app.get("/",(req,res)=>{
    res.render("index")
})

// ===========================================  register : get
app.get("/register",(req,res)=>{
   
    res.render("register")
})
//=================================================
app.post("/register",async(req,res)=>{
    try {
        const {username,password}=req.body
        const user=await User.findOne({username: username})
        if(user) return res.status(201).send("user already exist")
        bcrypt.hash(password, saltRounds, async (err, hash)=> {
            // Store hash in your password DB.
        const newUser=new User({
            username:username,
            password:hash
        })
        await newUser.save()
        res.status(201).redirect("/login")
        });
        
    } catch (error) {
        res.status(500).send(error.message)
    }
})

//============================================
const checkLoggedn=(req,res,next)=>{
    if(req.isAuthenticated()){
        return res.redirect("/profile")
    }
    next()
}
app.get("/login",checkLoggedn,(req,res)=>{
    
    res.render("login")   
})

//=========================================================
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login',
  successRedirect:"/profile",
  failureRedirect:"/login"
 }),
  function(req, res) {
    res.redirect('/');
  });
//===========================================================

const chenAuthentication=(req,res,next)=>{
    if(req.isAuthenticated()){
        return next()
    }else{
        res.redirect("/login")
    }
}

app.get("/profile",chenAuthentication,(req,res)=>{
    res.render("profile")
    
})
//========================================================
app.get("/logout",(req,res)=>{
    try {
        req.logout((err)=>{
            if(err){
                return next(err)
            }
            res.redirect("/")
        })
    } catch (error) { 
        res.status(500).send(err.message)
    
    }
})

module.exports=app