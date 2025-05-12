require('dotenv').config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const fs = require("fs");
const Joi = require("joi");


const saltRounds = 12;

const port = process.env.PORT || 3001;
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
app.use("/js", express.static(__dirname + "/js"));

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

function isValidSession(req) {
    if (req.session.loggedIn) {
        return true;
    } else {
        return false;
    }
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect("/login");
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    } else {
        return false;
    }
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "This user is not authorized to access this page."});
        return;
    } else {
        next();
    }
}

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

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user"});
    req.session.loggedIn = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
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

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, user_type: 1, name: 1, __id: 1 }).toArray();
    if (result.length != 1) {
        res.send("<p>Invalid email</p></br><a href='/login'>Try again</a>");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.loggedIn = true;
        req.session.name = result[0].name;
        req.session.email = email;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;
        let css = `<link rel="stylesheet" href="/css/members.css">`;

        res.redirect('/members');
        return;
    } else {
        res.send("<p>Incorrect password</p></br><a href='/login'>Try again</a>");
        return;
    }

});

app.get('/members', sessionValidation, (req, res) => {
        let css = `<link rel="stylesheet" href="/css/members.css">`;
        let name = req.session.name;
        res.render("members", { name: name, css: css });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    let result = await userCollection.find().project({name: 1, user_type: 1}).toArray();
    res.render("admin", {users: result});
})

app.post("/promoteUser/:name", async (req, res) => {
    let name = req.params.name;
    await userCollection.updateOne({"name": name}, {$set : {user_type: "admin"}});
    res.redirect('/admin');
})

app.post("/demoteUser/:name", async (req, res) => {
    let name = req.params.name;
    await userCollection.updateOne({"name": name}, {$set : {user_type: "user"}});
    res.redirect('/admin');
})

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