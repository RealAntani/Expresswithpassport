const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

app.use(logger('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

let users = [];
try {
  const usersData = fs.readFileSync('users.json', 'utf8');
  users = JSON.parse(usersData);
} catch (error) {
  console.error('Error loading users:', error);
}

passport.use(new LocalStrategy((username, password, done) => {
  const user = users.find(user => user.username === username);
  if (!user) {
    return done(null, false, { message: 'Incorrect username.' });
  }

  const { salt, key, cost, blockSize, parallelization } = user.passwordParams;
  crypto.scrypt(password, salt, 64, { N: cost, r: blockSize, p: parallelization }, (err, derivedKey) => {
    if (err) return done(err);
    if (key === derivedKey.toString('hex')) {
      return done(null, user);
    } else {
      return done(null, false, { message: 'Incorrect password.' });
    }
  });
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  user ? done(null, user) : done(new Error('User not found.'));
});

const handleSignup = (options) => async (req, res) => {
  const { username, password } = req.body;
  if (users.some(u => u.username === username)) {
    return res.status(400).send('Username already exists.');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  crypto.scrypt(password, salt, 64, { N: options.cost, r: options.blockSize, p: options.parallelization }, (err, derivedKey) => {
    if (err) {
      console.error('Error hashing password:', err);
      return res.status(500).send('Error creating user.');
    }

    const newUser = {
      id: users.length + 1,
      username: username,
      passwordParams: {
        salt: salt,
        key: derivedKey.toString('hex'),
        cost: options.cost,
        blockSize: options.blockSize,
        parallelization: options.parallelization
      }
    };
    users.push(newUser);

    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
    console.log('User created successfully');
    res.redirect('/login');
  });
};

const fastOptions = { cost: 16384, blockSize: 8, parallelization: 1 };
const slowOptions = { cost: 16384, blockSize: 8, parallelization: 50 };

app.post('/signup/fast', handleSignup(fastOptions));
app.post('/signup/slow', handleSignup(slowOptions));

app.get('/login', (req, res) => res.sendFile('login.html', { root: __dirname }));
app.get('/signup', (req, res) => res.sendFile('signup.html', { root: __dirname }));

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), (req, res) => res.redirect('/'));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login');
});

app.post('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});


app.get('/', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    Welcome to your private page, ${req.user.username}!
    <form action="/logout" method="post">
      <button type="submit">Logout</button>
    </form>
  `);
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
