
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();


console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine' , 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

// app use session package
app.use(session({
  secret: "Little secret.",
  resave: false,
  saveUninitialized: false,
}));


app.use(passport.initialize());
app.use(passport.session());


// connecting to mongodb
mongoose.connect('mongodb://127.0.0.1:27017/userDB');

// setting a new Schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


// setting mongoose model
const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ username: profile.emails[0].value, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// GET requests
app.get("/", function(req,res){
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {
   scope: ['profile',"email"]
 }));

app.get("/auth/google/secrets", passport.authenticate("google",{
  failureRedirect: "/login" }),
  function(req,res){
    // successfully authentication, redirect to secrets page
    res.redirect("/secrets");

});


app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/secrets", function(req,res){
  User.find({"secret": {$ne: null}} ).then((foundUsers)=>{
    if(foundUsers){
      res.render("secrets", {usersWithSecrets : foundUsers});
    }
  })
  .catch((err)=>{
    console.log(err);
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id).then((foundUser)=>{
    if(foundUser){
      foundUser.secret = submittedSecret;
      foundUser.save().then(()=>{
        res.redirect("/secrets");
      });
    }else{
      console.log("User not found");
    }
  })
  .catch((err)=>{
    console.log(err);
  });
});


app.get("/logout", function(req,res){
  req.logout(function(err){
    if(err){
      console.log(err);
    }else{
      res.redirect("/");
    }


});

  });


// POST requests
app.post("/register",function(req, res){
  User.register({username: req.body.username},req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res, function(){
        res.redirect("/secrets");
      })

    }
  })

});


app.post("/login", function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password

  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res, function(){
        res.redirect("/secrets");
      })
    }
  } )


});

app.listen(3000, function(req,res){
  console.log("Server is starting at port 3000");
});
