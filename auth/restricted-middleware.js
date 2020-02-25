const bcrypt = require("bcryptjs");

const db = require("./auth-model");

const authenticateUser = (req, res, next) => {

  if (!req.headers || !req.headers.username || !req.headers.password)
  { res.status(400).json({message: "Username and password are both required."})}

  else
  {
    // see if user exists
    db.getUserByUsername(req.headers.username)
    .then(dbInfo => {
      if (dbInfo && bcrypt.compareSync(req.headers.password, dbInfo.password))
        { next(); }
      else
        { res.status(401).json({ message: "Invalid Credentials."})}
    })
    .catch(error => { res.status(401).json({ message: "You shall not pass."})})
  }
}

module.exports = authenticateUser;