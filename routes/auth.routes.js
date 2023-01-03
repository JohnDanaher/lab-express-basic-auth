const bcrypt = require('bcryptjs')
const express = require('express');
const mongoose = require('mongoose');
const { isLoggedIn, isLoggedOut} = require('../middleware/route-guard');
const router = express.Router();
const saltRounds = 10;

const User = require('../models/User.model')

// Signup
router.get('/signup', isLoggedOut, (req, res) => {
    res.render('auth/signup', {loggedIn: false})
})

router.post('/signup', isLoggedOut, (req, res, next) => {
    const {username, password} = req.body;

    bcrypt.hash(password, saltRounds)
    .then(hash => User.create({username, passwordHash: hash}))
        .then((newUser)=> res.redirect(`/auth/profile/${newUser.username}`))
        .catch(error => {
            if (error instanceof mongoose.Error.ValidationError) {
              res.status(500).render('auth/signup', { errorMessage: error.message });
            } else if (error.code === 11000) {
              res.status(500).render('auth/signup', {
                 errorMessage: 'Username taken. Please try a different one'
              });
            } else {
              next(error);
            }
          });
});

router.get('/login', isLoggedOut, (req, res) => {
    res.render('auth/login', {loggedIn: false})
})

router.post('/login', isLoggedOut, (req, res) => {
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

router.get('/profile/:username', isLoggedIn, (req, res) => {
    const { currentUser } = req.session;
    currentUser.loggedIn = true;
    res.render("auth/profile", currentUser)
});

router.get('/main', isLoggedIn, (req, res) => {
    res.render('auth/main', {loggedIn: true})
})

router.get('/private', isLoggedIn, (req, res) => {
    res.render('auth/private', {loggedIn: true})
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
