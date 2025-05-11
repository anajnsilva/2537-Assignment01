require('dotenv').config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const fs = require("fs");
const Joi = require("joi");


const saltRounds = 12;

const port = process.env.PORT || 3000;
const app = express();

const expireTime = 1 * 60 * 60 * 1000;

const mongoHost = process.env.MONGODB_HOST;
const mongoUser = process.env.MONGODB_USER;
const mongoPWD = process.env.MONGODB_PASSWORD;
const mongoDataBase = process.env.MONGODB_DATABASE;
const mongoSecret = process.env.MONGODB_SESSION_SECRET;
const nodeSecret = process.env.NODE_SESSION_SECRET;

var database = require('./dbConenction.js').database;

const userCollection = database.db(mongoDataBase).collection('users');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use("/public", express.static("./public"));
app.use("/css", express.static(__dirname + "/css"));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongoUser}:${mongoPWD}@${mongoHost}/${mongoDataBase}`,
    crypto: {
        secret: mongoSecret
    }
});

app.use(session(
    {
        secret: nodeSecret,
        store: mongoStore,
        resave: false,
        saveUninitialized: true
    })
);

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    let css = `<link rel="stylesheet" href="/css/index.css">`;
    let loggedIn = req.session.loggedIn;
    let name = req.session.name;
    res.render("index", { loggedIn: loggedIn, name: name, css: css });
});

app.get('/signup', (req, res) => {
    let css = `<link rel="stylesheet" href="/css/login.css">`;
    res.render("signup", { css: css });
});

app.post('/submitUser', async (req, res) => {
    let name = req.body.name;
    let email = req.body.email;
    let password = req.body.password;

    const schema = Joi.object(
        {
            name: Joi.string().required(),
            email: Joi.string().required(),
            password: Joi.string().max(20).required()
        }
    );

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        if (name === "") {
            res.send("<p>Name is required.</p></br><a href='/signup'>Try again</a>");
            return;
        }
        if (email === "") {
            res.send("<p>Email is required.</p></br><a href='/signup'>Try again</a>");
            return;
        }
        if (password === "") {
            res.send("<p>Password is required.</p></br><a href='/signup'>Try again</a>");
            return;
        }
        res.redirect('/signup');
        return;
    }

    let hashedPassword = await bcrypt.hashSync(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
    req.session.loggedIn = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.render("/members", { name: name });
});

app.get('/login', (req, res) => {
    let css = `<link rel="stylesheet" href="/css/login.css">`;
    res.render("login", { css: css });
});

app.post('/loggingIn', async (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    const schema = Joi.string().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        if (email === "") {
            res.send("<p>Email is required.</p></br><a href='/login'>Try again</a>");
            return;
        }
        res.redirect('/login');
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, name: 1, __id: 1 }).toArray();
    if (result.length != 1) {
        res.send("<p>Invalid email</p></br><a href='/login'>Try again</a>");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.loggedIn = true;
        req.session.name = result[0].name;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;
        let css = `<link rel="stylesheet" href="/css/members.css">`;

        res.render('members', {css: css, name: req.session.name});
        return;
    } else {
        res.send("<p>Incorrect password</p></br><a href='/login'>Try again</a>");
        return;
    }

});

app.get('/members', (req, res) => {
    if (!req.session.loggedIn) {
        res.redirect('/');
        return;
    } else {
        let css = `<link rel="stylesheet" href="/css/members.css">`;
        let name = req.session.name;
        res.render("members", { name: name, css: css });
    }
});


app.post("/logout", function (req, res) {

    if (req.session) {
        req.session.destroy(function (error) {
            if (error) {
                res.status(400).send("Unable to log out")
            } else {
                // session deleted, redirect to home
                res.redirect("/");
            }
        });
    }
});

app.get("*dummy", (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, function () {
    console.log("Listening on port " + port + "!");
});