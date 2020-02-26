const express = require("express");
const cors = require("cors");
const session = require("express-session");

const knexStore = require("connect-session-knex")(session);
const knex = require("./data/db-config");

const authRouter = require("./auth/auth-router");
const restricted = require("./auth/restricted-middleware");

const server = express();

const sessionConfig = {
  name: "user",
  secret: "this is a secret value",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 10,
    secure: false,
    httpOnly: true
  },
  store: new knexStore({
    knex,
    tablename: "sessions",
    createtable: true,
    sidfieldname: "sid",
    clearInterval: 1000 * 60 * 15
  })

}

const serverConfig = {
  origin: "http://localhost:1234",
  credentials: true
}

server.use(express.json());
server.use(cors(serverConfig));

server.use(session(sessionConfig));

server.use("/api/auth", authRouter);
// server.use("/api/restricted", restricted);

server.get("/", (req, res) => {
  console.log("req.session:", req.session);
  res.status(200).json({message: "API is working."})
})

module.exports = server;