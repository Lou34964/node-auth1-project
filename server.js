const express = require("express");

const authRouter = require("./auth/auth-router");
const restricted = require("./auth/restricted-middleware");

const server = express();
server.use(express.json());

server.use("/api/auth", authRouter);
server.use("/api/restricted", restricted);

server.get("/", (req, res) => {
  res.status(200).json({message: "API is working."})
})

module.exports = server;