//jshint esversion:6

require('dotenv').config()
const express = require("express")
const bodyParser = require("body-parser")
const ejs = require("ejs")
const mongoose = require("mongoose")
//const encrypt = require("mongoose-encryption")
//const md5 = require("md5")
//const bcrypt = require("bcrypt")
//const saltRounds = 10;
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate")


const app = express();

app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

// Session
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized:true,
}))

// Passport
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect(process.env.MONGO_URL, {useNewUrlParser: true, useUnifiedTopology: true})
mongoose.set("useCreateIndex", true)

// Schema

const userSchema = new mongoose.Schema ({
    email: {
        type: String,
        required: false
    },
    password: {
        type: String,
        required: false
    },
    googleId: String,
    facebookId: String,
    secret: String,
})

userSchema.plugin(passportLocalMongoose, { usernameUnique: false });
userSchema.plugin(findOrCreate)

// Model

const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy());
 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile)
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Routes

app.get("/", function(req, res) {
    res.render("home")
})

// Google OAuth
app.get('/auth/google',
    passport.authenticate("google", { scope: ["profile"] }));

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    });

// Facebook OAuth
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

// Register
app.route("/register")
    .get(function(req, res) {
        res.render("register")
    })

    .post(function(req, res) {
        User.register({username: req.body.username}, req.body.password, function(err, user) {
            if (err) {
                console.log(err)
                res.redirect("/register")
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets")
                })
            }
        })
    })

// Login
app.route("/login")
    .get(function(req, res) {
        res.render("login")
    })

    .post(function(req, res) {
        const user = new User ({
            username: req.body.username,
            password: req.body.password
        })

        req.login(user, function (err) {
            if (err) {
                console.log(err)
            } else {
                passport.authenticate("local", { successFlash: 'Welcome!' })(req, res, function () {
                    res.redirect("/secrets")
                })
            }
        })
    })

// Logout
app.route("/logout")
    .get(function (req, res) {
        req.logout();
        res.redirect("/")
    })

// Secrets
app.route("/secrets")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            User.find({"secret": { $ne: null}}, function (err, foundSecrets) {
                if (!err) {
                    if (foundSecrets) {
                        res.render("secrets", {users: foundSecrets})
                    }
                } else {
                    console.log(err)
                }
            })
        } else {
            res.redirect("/login")
        }
    })

app.route("/submit")
    .get(function (req, res) {
        if (req.isAuthenticated()){
            res.render("submit");
        } else {
            res.redirect("/login")
        }
    })

    .post(function (req, res) {
        const secret = req.body.secret
        User.findById(req.user.id, function(err, foundUser) {
            if (!err) {
                if (foundUser) {
                    foundUser.secret = secret;
                    foundUser.save(function() {
                        res.redirect("/secrets")
                    });
                } else {
                    res.redirect("/")
                }
            } else {
                console.log(err)
            }
        }) 
    })

app.listen(process.env.PORT || 3000, function() {
    console.log("Server running on port 3000")
})