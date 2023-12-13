const express = require('express');
const app = express();
const port = 3000;

const passport = require('passport')
const LocalStrategy =require('passport-local')
const crypto = require('crypto')

passport.use(new LocalStrategy(function verify(username, password, cb) {
    db.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false, { message: 'Incorrect username or password.' }); }
  
      crypto.pbkdf2(password, user.salt, 310000, 32, 'puspa231', function(err, hashedPassword) {
        if (err) { return cb(err); }
        if (!crypto.timingSafeEqual(user.hashed_password, hashedPassword)) {
          return cb(null, false, { message: 'Incorrect username or password.' });
        }
        return cb(null, user);
      });
    });
  }));