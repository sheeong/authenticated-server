const jwt = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  //user has already had their email and password authenticated
  res.send({ token: tokenForUser(req.user) } );
}

exports.signup = function (req, res, next) {
  //console.log(req.body);

  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: 'Email and password must not be empty'});
  }
  // see if email exists
  User.findOne({ email: email}, function(err, existingUser) {
    if (err) { return next(err); }

    //email exists, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use'});
    }

    //create and save user record
    const user = new User({ email: email, password: password});
    user.save(function(err) {
      if (err) { return next(err); }
    });

    //respond to request as successful creation
    res.json({ token: tokenForUser(user)});
  });
}
