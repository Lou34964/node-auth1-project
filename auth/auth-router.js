const bcrypt = require("bcryptjs");
const express = require("express");

const middleware = require("./restricted-middleware");

const db = require("./auth-model");

const router = express.Router();

// GET all users
router.get("/users", middleware, (req, res) => {

  db.getUsers()
    .then(users => {
      res.status(200).json(users);
    })
    .catch(error => {
      res.status(500).json({message: "Could not get users."})
    })
})

// GET a user by ID
router.get("/:id", (req, res) => {

  db.getUserByID(req.params.id)
    .then(user => {
      res.status(200).json(user);
    })
    .catch(error => {
      res.status(500).json({message: "Could not get user."})
    })
})


// POST: register a new user
router.post("/signup", (req, res) => {

  if (!req.body || !req.body.username || !req.body.password)
    { res.status(400).json({message: "Username and password are both required."})}

  else
  {
    let hashedPassword = bcrypt.hashSync(req.body.password, 14);
    req.body.password = hashedPassword;

    db.addUser(req.body)
      .then(usersAdded => {
        res.status(200).json(usersAdded);
      })
      .catch(error => {
        res.status(500).json({message: "Could not add user."})
      })
  }
})

// POST: log in a user
router.post("/login", (req, res) => {

  if (!req.body || !req.body.username || !req.body.password)
    { res.status(400).json({message: "Username and password are both required."})}

  else
  {
    // see if user exists
    db.getUserByUsername(req.body.username)
      .then(dbInfo => {
        if (dbInfo && bcrypt.compareSync(req.body.password, dbInfo.password))
          { res.status(200).json({message: "Welcome, " + dbInfo.username}) }
        else
          { res.status(401).json({ message: "Invalid Credentials."})}
    })
      .catch(error => { res.status(401).json({ message: "You shall not pass."})})
  }
})


module.exports = router;