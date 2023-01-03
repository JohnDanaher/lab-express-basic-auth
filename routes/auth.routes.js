const bcrypt = require('bcryptjs')
const express = require('express');
const isLoggedIn = require('../../../lesson-07/basic-auth/middleware/isLoggedIn');
const router = express.Router();
const saltRounds = 10;

const User = require('../models/User.model')

// Signup
router.get('/signup', (req, res) => {
    res.render('auth/signup')
})

router.post('/signup', (req, res) => {
    const {username, password} = req.body;

    bcrypt.hash(password, saltRounds)
    .then(hash => User.create({username, passwordHash: hash}))
        .then((newUser)=> res.redirect(`/auth/profile/${newUser.username}`))
    });

router.get('/login', (req, res) => {
    res.render('auth/login')
})

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    User.findOne({username})
    .then(foundUser => {
        return bcrypt.compare(password, foundUser.passwordHash)
        .then(result => {
         if(result == true) {
            req.session.currentUser = foundUser.toObject();
            delete req.session.currentUser.password;
            res.redirect(`/auth/profile/${foundUser.username}`)
         } else {
            res.render('auth/login', {errorMessage: 'Incorrect password'})
         }      
        })
    })
    
})

router.get('/profile/:username', (req, res) => {
    const {username} = req.params;
    User.findOne({username})
    .then(foundUser => res.render('auth/profile', foundUser))
    .catch(err => console.log(err))
});

router.get('/main', isLoggedIn, (req, res) => {
    res.render('auth/main')
})

router.get('/private', isLoggedIn, (req, res) => {
    res.render('auth/private')
})

router.get("/logout", isLoggedIn, (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.log(err)
      }
  
      res.redirect("/");
    });
  });

module.exports = router;
