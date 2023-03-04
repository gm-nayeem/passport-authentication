const express = require("express");
const cors = require("cors");
const ejs = require("ejs");
const morgan = require("morgan");
require("./config/database");
require("dotenv").config();
require("./config/passport");
const User = require("./models/User");
const bcrypt = require("bcrypt");

const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo");

const app = express();

// middleware
app.set("view engine", "ejs");
app.use(morgan("dev"));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// session
app.set("trust proxy", 1); // trust first proxy
app.use(
    session({
        secret: "keyboard cat",
        resave: false,
        saveUninitialized: true,
        store: MongoStore.create({
            mongoUrl: process.env.MONGO_URL,
            collectionName: "sessions",
        }),
    })
);

// passport
app.use(passport.initialize());
app.use(passport.session());


// auth middleware
const authMiddleware = (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect("/profile");
    }
    return next();
}

// profile middleware
const prifileMiddleware = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    return res.redirect("/login");
}


// base url
app.get("/", (req, res) => {
    res.render("index");
});

// register : get
app.get("/register", authMiddleware, (req, res) => {
    res.render("register");
});

// register : post
app.post("/register", async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (user) return res.status(400).send("user already exists");

        bcrypt.hash(req.body.password, 10, async (err, hash) => {
            const newUser = new User({
                username: req.body.username,
                password: hash,
            });
            await newUser.save();
            res.redirect("/login");
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// login : get
app.get("/login", authMiddleware, (req, res) => {
    res.render("login");
});

// login : post
app.post(
    "/login",
    passport.authenticate("local", {
        failureRedirect: "/login",
        successRedirect: "/profile",
    })
);

// profile protected route
app.get("/profile", prifileMiddleware, (req, res) => {
    res.render("profile", { username: req.user.username });
});

// logout route
app.get("/logout", (req, res) => {
    try {
        req.logout((err) => {
            if (err) {
                return next(err);
            }
            res.redirect("/");
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

module.exports = app;