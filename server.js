const {globalVariables} = require('./config/configuration')
const express = require('express');
const path = require('path');
const ejs = require('ejs');
const port = process.env.PORT || 3000;
const mongoose = require('mongoose');
const Message = require('./models/Message');
const session = require('express-session');
const cookieParser = require('cookie-parser')
const MongoStore = require('connect-mongo');
const flash = require('connect-flash');
const logger = require('morgan');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/Users');
const {isLoggedIn} = require('./config/authorizations');
const Campaign = require('./models/Campaign');
const randomstring = require('randomstring')

const app = express();

// DB Connection
mongoose.connect('mongodb://localhost/waawnonymous')
    .then(dbconnect => console.log('Database connection successful'))
    .catch(error => console.log('Database connection error:', error.message));

// Setting up express instance
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.locals.moment = require('moment');

app.use(cookieParser());
app.use(session({
    secret: 'hhhhhhhhhhhhhhhhhhhhhhhhhhhh',
    resave: true,
    saveUninitialized: true,
    cookie: {maxAge: Date.now() + 3600000},
    store: MongoStore.create({
        mongoUrl: 'mongodb://localhost/waawnonymous',
        ttl: 14 * 24 * 60 * 60
    })
}));

app.use(logger('dev'));

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({usernameField: 'email', passReqToCallback: true}, async(req, email, password, done) => {
    await User.findOne({email})
    .then(async(user) => {
        if (!user) {return done(null, false, req.flash('error-message', 'User not found. Please register and try again.'));}

        bcrypt.compare(password, user.password, (err, passwordMatch) => {
            if (err){
                return err;
            }
            if (!passwordMatch) return done(null,false, req.flash('error-message', 'Password incorrect'))

            return done(null, user, req.flash('success-message', 'Login successfully'));
        });
    });
}));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function(err, user){
        done(err, user);
    });
});

// Use flash
app.use(flash());

// Use Global Variables
app.use(globalVariables);

app.get('/', async (req, res) => {
    // let allmessages = await Message.find({}).sort({_id:-1})
    // console.log(allmessages);
    res.redirect('/user/login');
});

app.post('/message/create-message', async (req, res, next) =>{
    let {message} = req.body;

    if(!message){
        req.flash('error-message', "Please enter a message");
       return res.redirect('/');
    }
    let newMessage = new Message({
        message
    });
    console.log(message);
    await newMessage.save()
    .then(() => {
        req.flash('success-message', 'Message created succesfully')
        res.redirect('/')
    })
    .catch((error) => {
        req.flash('error-message', error.message)
        res.redirect('/')
    })
    // res.redirect('/')
});
app.get('/campaign/single-campaign/:campaignId', async (req, res) => {
    
})

app.get('/message/delete-message/:messageId', async (req, res) =>{
    const {messageId} = req.params;

    const deletedMsg = await Message.findByIdAndDelete(messageId);
    if (!deletedMsg){
        req.flash('error-message', 'Message was not deleted');
        return res.redirect('back');
    }
    req.flash('success-message', 'Message deleted succesfully')
    res.redirect('back');
})


app.get('/user/register', (req, res) => {
    res.render('register')
});

app.post('/user/register', async (req, res) => {
    let {email, fullName, password, confirmPassword} = req.body;

    if (password != confirmPassword) {
        req.flash('error-message', "Passwords do not match")
        return res.redirect('back');
    }
    let userExists = await User.findOne({email});

    if (userExists){
        req.flash('error-message', "Email already taken")
        return res.redirect('back');
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt)

    let newUser = new User({
        email,
        fullName,
        password: hashedPassword,
    })

    newUser = await newUser.save();

    if(!newUser){
        req.flash('error-message', "Something went wrong, please try again")
        return res.redirect('back');
    }

    req.flash('success-message', "Registration successful, you can login")
    return res.redirect('/user/login');
});

app.get('/user/login', (req, res) => {
    if (req.user) res.redirect('/user/profile')
    res.render('login');
})

app.get('/user/profile', isLoggedIn, async (req, res) => {
    let userCampaigns = await Campaign.find({ user: req.user._id })
    .populate('user')
    console.log(userCampaigns)
    res.render('profile', {userCampaigns});
});

app.post('/user/login', passport.authenticate('local', {
    successRedirect: '/user/profile',
    failureRedirect: '/user/login',
    failureFlash: true,
    successFlash: true,
    session: true,
    })
);
app.get('/campaign/create-campaign', isLoggedIn, (req, res) => {
    res.render('campaign')
})
app.post('/campaign/create-campaign', isLoggedIn, async (req, res) => {
    let loggedInUser = req.user;
    let { title } = req.body;
    let campaignLink = `${req.headers.origin}/campaign/single-campaign/${randomstring.generate()}`
    
    let newCampaign = new Campaign({
title,
user: loggedInUser._id,
link: campaignLink,
    });
    await newCampaign.save();
    if(!newCampaign){
        req.flash('error-message', 'An error occured while creating campaign')
        return res.redirect('back')
    }
    req.flash('success-message', 'Campaign Created successfully')
        return res.redirect('back')
}); 

app.get('/campaign/single-campaign/:campaignId', async (req, res) => {
 const singleCampaign =  await Campaign.findOne({link: `http://localhost:3000/campaign/single-campaign/${req.params.campaignId}`})
 .populate()
console.log(singleCampaign)
})


app.get('/user/logout', (req, res) => {
    req.logOut();

    req.flash('success-message', 'USer logged out successfully')

    res.redirect('/user/login');
});

app.listen(port, () => console.log(`Server listening on port:: ${port}`));