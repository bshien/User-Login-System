const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const async = require('async');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
//const sesTransport = require('nodemailer-ses-transport');
var AWS = require('aws-sdk');
// require('dotenv').config();

// const SESCREDENTIALS = {
//   accessKeyId : process.env.ID ,
//   secretAccessKey : process.env.SECRET
// };

// console.log('region: ', process.env.REGION);

 // configure AWS SDK
 AWS.config.update({
  // accessKeyId: SESCREDENTIALS.accessKeyID,
  // secretAccessKey: SESCREDENTIALS.secretAccessKey,
  // region: process.env.REGION,
  region: "us-west-2",
  "Statement": [
    {
        "Effect": "Allow",
        "Action": "ses:SendRawEmail",
        "Resource": "*"
    }
]
});



// User model
const User = require('../models/User');
// Login Page
router.get('/login', (req,res) => res.render('login'));

// Register Page
router.get('/register', (req,res) => res.render('register'));

// Forgot Password Page
router.get('/forgot', (req,res) => res.render('forgot'));

// New Password Page
// router.get('/newpass', (req,res) => res.render('newpass'));

router.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/users/forgot');
    }
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      console.log("this", user);
      console.log("req1", req.params);
    });
   
    res.render('reset', {
      user: req.user,
      token: user.resetPasswordToken
    });
  });
});



router.post('/reset/:token', function(req, res) {
  console.log('req2', req.params);
  
  const pass1 = req.body.password;
  const pass2 = req.body.password2;
  if(pass1 != pass2){
    req.flash('error', "Passwords didn't match.");
    
    return res.redirect('/users/forgot');
    
  }
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        console.log("wit", user);
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          
          return res.redirect('back');
        }
        bcrypt.genSalt(10, (err, salt) => bcrypt.hash(req.body.password, salt, (err, hash) =>
        {
        if(err) throw err;
        // Set password to hashed
        user.password = hash;
              // Save user
        // user.save(function(err) {
        //   if(err) throw err;
        // });
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          
          done(err, user);
          
        });
         
        }))
        
      });
    },
    function(user, done) {
      let smtpTransport = nodemailer.createTransport({
        SES: new AWS.SES({
            apiVersion: '2010-12-01'
        })
    });
      var mailOptions = {
        to: user.email,
        from: 'testmailliamtset1682@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/');
  });
});

// Forgot Handle
router.post('/forgot', (req, res, next) => {
    const { email } = req.body;
    console.log('Email:', email)
    let errors = [];

    if(!email){
        
        errors.push({ msg: 'Please fill in all fields' });
    }
    if(errors.length > 0) {
        res.render('forgot', {
            errors,
            email,
            
        });
       
    } else {
        req.flash('success_msg', 'Email sent');
        
        async.waterfall([
            function(done) {
              crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
              });
            },
            function(token, done) {
              User.findOne({ email: req.body.email }, function(err, user) {
                if (!user) {
                  req.flash('error', 'No account with that email address exists.');
                  return res.redirect('/users/forgot');
                }
        
                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        
                user.save(function(err) {
                  done(err, token, user);
                });
              });
            },
            function(token, user, done) {
              let smtpTransport = nodemailer.createTransport({
                SES: new AWS.SES({
                    apiVersion: '2010-12-01'
                })
            });
              var mailOptions = {
                to: user.email,
                from: "testmailliamtset1682@gmail.com",
                subject: 'Node.js Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                  'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                  'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
                  'If you did not request this, please ignore this email and your password will remain unchanged.\n'
              };
              smtpTransport.sendMail(mailOptions, function(err) {
                req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
                done(err, 'done');
              });
            }
          ], function(err) {
            if (err) return next(err);
            res.redirect('/users/forgot');

          });
          //res.redirect('/users/login');
    }
    
});



// Register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Check required fields
    if(!name || !email || !password || !password2) {
        errors.push({ msg: 'Please fill in all fields' });

    }

    // Check passwords match
    if(password !== password2) {
        errors.push({ msg: 'Passwords do not match' });

    }

    // Check pass length
    if(password.length < 6) {
        errors.push({ msg: 'Password should be at least 6 characters' });

    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2

        });
    } else {
        //  Validation passed
        User.findOne({ email: email })
          .then(user => {
              if(user) {
                  // User exist
                  errors.push({msg: 'Email is already registered' });
                  res.render('register', {
                      errors,
                      name,
                      email,
                      password,
                      password2
                  });
                } else {
                    const newUser = new User({
                        name,
                        email,
                        password
                    });
                    
                    // Hash Password
                    bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash) =>
                    {
                       if(err) throw err;
                       // Set password to hashed
                    
                       newUser.password = hash; 
                       // Save user
                       newUser.save()
                         .then(user=> {
                             req.flash('success_msg', 'You are now registered and can log in');
                             res.redirect('/users/login');
            
                         })
                         .catch(err => console.log(err));
                    }) )

    


                }
            
                
              
          });


    }
});

// Login Handle
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/users/login',
  failureFlash: true
  })(req, res, next);
});

// Logout Handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
})
module.exports = router;

