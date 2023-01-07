//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
/*const encrypt = require ("mongoose-encrypt") removed due to hashing.
const md5 = require ("md5");
const bcrypt = require ("bcrypt");
const saltRounds = 10;*/
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded ({extended: true}));

// Express-Session Usage
app.use(session({
  secret: "our little secret.",
  resave: false,
  saveUninitialized: false
}));

// Initializing Passport or Passport Usage
app.use(passport.initialize());
app.use(passport.session());

// mongooose connect to mongoDB
mongoose.connect( process.env.db, {useNewUrlParser: true});

// create schema
const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// Add plugins (for database encryption)
/*userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });  we remove the plugin due to Hashing*/

// Using Passport-local-mongoose
userSchema.plugin(passportLocalMongoose);
// Using findOrCreate plugin
userSchema.plugin(findOrCreate);

// create model
const User = new mongoose.model ("User", userSchema);

// Configure Passport-local-mongoose
// create a local login strategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
// for local authentication only
/*passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());*/

// for all kind of authentication
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
/*passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});*/

// configure GoogleStrategy using passport
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
  res.render("home");
});

// Get route for our google button (authentication request)
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

// authentication request, redirecting me to secret page
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/secrets", function(req,res){
  User.find({"secret": {$ne: null}}, function (err, foundUsers){
    if(err) {
      console.log(err);
    } else {
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;

  console.log(req.user.id);
  User.findById (req.user.id, function(err, foundUser){
    if (err){
      console.log(err);
    } else {
      if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
        res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res) {
  req.logout(function(err) {
    if(err){
      console.log(err);
    }
    res.redirect('/');
  });
});

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err) {
      console.log(err)
      res.redirect("/register")
    } else {
      passport.authenticate("local") (req, res, function() {
        res.redirect ("/secrets");
      });
    }
  });

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User ({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if(err){
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });
});



app.post("/login", function (req,res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets")
      });
    }
  });
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username}, function(err, foundUser) {
  //   if(err){
  //     console.log(err);
  //   } else {
  //     if(foundUser){
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if(result == true) {
  //           res.render("secrets");
  //         }
  //       });
  //     }
  //   }
  // });
});


app.listen(3000, function(){
  console.log("server running on port 3000");
});
