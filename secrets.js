var express = require("express");
var app = express();
var mongoose = require("mongoose");

mongoose.connect("mongodb://localhost/dojosecrets");

var validateEmail = function(email) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email);
};

var birthdayVal = function(birthday) {
    var diff = Date.now() - birthday.getTime();
    var age = new Date(diff);
    var final = Math.abs(age.getUTCFullYear() - 1970);
    if (final < 13) {
        return false;
    }
    else {
        return true;
    }
}

var CommentSchema = new mongoose.Schema ({
    comment: {type: String, required: [true, "Please type in a comment"],
    minlength: [5, "Comments must be at least 5 characters long"]}
}, {timestamps: true});

var SecretSchema = new mongoose.Schema ({
    secret: {type: String, required: [true, "Please type in a comment"],
    minlength: [5, "Secrets must be at least 5 characters long"]},

    comments: [CommentSchema]
}, {timestamps: true});

var UserSchema = new mongoose.Schema({
    first_name: {type: String, required: [true, "Please type in your first name"],
    minlength: [2, "First name must be at least 2 characters long"]},

    last_name: {type: String, required: [true, "Please type in your last name"],
    minlength: [2, "Last name must be at least 2 characters long"]},

    email: {type: String, required: [true, "Please type in your email"],
    validate: [validateEmail, "Not a valid email address"], unique: true},

    password: {type: String, required: [true, "Please type in your password"],
    minlength: [5, "Password must be at least 5 characters long"]},

    birthday: {type: Date, required: [true, "Please enter your birthday"],
    validate: [birthdayVal, "You must be at least 13 years old to register"]},

    secrets: [SecretSchema]
}, {timestamps: true});

var uniqueValidator = require("mongoose-unique-validator");
UserSchema.plugin(uniqueValidator, {message: "Email already exists in the system"});
mongoose.model("Comment", CommentSchema);
mongoose.model("Secret", SecretSchema);
mongoose.model("User", UserSchema);

var Comment = mongoose.model("Comment");
var Secret = mongoose.model("Secret");
var User = mongoose.model("User");

var bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({ extended: true }));

var path = require("path");
app.set("views", path.join(__dirname, "./views"));
app.set("view engine", "ejs");

var session = require("express-session");
const flash = require("express-flash");
app.use(session({
    secret: "secretsecrets",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 }
}));
app.use(flash());

const bcrypt = require("bcrypt");

app.get("/", function(req, res) {
    res.render("start");
});

app.post("/register", function(req, res) {
    var first_name = req.body.first_name;
    var last_name = req.body.last_name;
    var email = req.body.email;
    var password = req.body.password;
    var birthday = req.body.birthday;

    var user = new User({first_name: first_name, last_name: last_name, email: email,
    password: password, birthday: birthday});

    user.save(function (err, user) {
        if (err) {
            for(var key in err.errors){
                req.flash("register", err.errors[key].message);
            }
            res.redirect("/");
        }
        else {
            var sess = req.session;
            let hash = bcrypt.hashSync(password, 10);
            user.password = hash;
            user.save();

            sess.login = true;
            sess.email = user.email;
            res.redirect("/secrets");
        }
    })
});

app.post("/login", function(req, res) {
    var email = req.body.email;
    var password = req.body.password;

    User.findOne({email: email}, function(err, user) {

        if (user == null) {
            req.flash("login", "Cannot find email. Please register for an account.");
            res.redirect("/");
        }
        else {
            if(bcrypt.compareSync(password, user.password)) {
                var sess = req.session;

                sess.login = true;
                sess.email = user.email;
                res.redirect("/secrets");
            }
            else {
                req.flash("login", "Incorrect password.");
                res.redirect("/");
            }
        }
    })
});

app.get("/secrets", function(req, res) {
    var sess = req.session;
    if (sess.login == null) {
        res.redirect("/");
    }
    else {
        var email = sess.email;
        User.findOne({email: email}, function (err, user) {
            if (err) {
                console.log("Cannot find user.");
            }
            else {
                Secret.find({}, function(err, secrets) {
                    if (err) {
                        console.log("Error. Secrets not found");
                    }
                    else {
                        res.render("home", {user: user, secrets: secrets.reverse()});
                    }
                })
            }
        })
    }
});

app.post("/secrets/process", function(req, res) {
    var sess = req.session;
    var secret = new Secret({secret: req.body.secret});
    secret.save(function(err) {
        if(err) {
            for(var key in err.errors){
                req.flash("secret", err.errors[key].message);
            }
            res.redirect("/secrets");
        }
        else {
            var email = sess.email;
            User.findOne({email: email}, function (err, user) {
                if (err) {
                    console.log("Cannot find user.");
                }
                else {
                    user.secrets.push(secret);
                    user.save();
                    res.redirect("/secrets");
                }
            })
        }
    })
});

app.get("/secrets/:id", function(req, res) {
    Secret.findOne({_id: req.params.id}, function(err, secret) {
        if (err) {
            console.log("Error. Data not found");
        }
        else {
            res.render("show", {secret, secret});
        }
    })
});

app.post("/secrets/:id/comment", function(req, res) {
    Secret.findOne({_id: req.params.id}, function(err, secret) {
        if (err) {
            console.log("Cannot find secret");
        }
        else {
            var comment = new Comment({comment: req.body.comment});

            comment.save(function(err) {
                if(err) {
                    for(var key in err.errors){
                        req.flash("comment", err.errors[key].message);
                    }
                    res.redirect("/secrets/" + req.params.id);
                }
                else {
                    secret.comments.push(comment);
                    secret.save();
                    res.redirect("/secrets/" + req.params.id);
                }
            })
        }
    });
});

app.get("/secrets/delete/:id", function(req, res) {
    Secret.deleteOne({_id: req.params.id}, function () {
        res.redirect("/secrets");
    })
});

app.get("/logout", function(req, res) {
    req.session.destroy();
    res.redirect("/");
});

app.listen(3579, function() {
    console.log("listening on port 3579");
});

/*
purplesmart@eq.net; twily123
20cooler@eq.net; dashie20
nightprincess@eq.net; lunamoon
*/