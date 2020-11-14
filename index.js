/**
 * This is a server
 */

const express = require("express");
const speakeasy = require("speakeasy");
// for establish user ID
const uuid = require("uuid");

const {JsonDB} = require('node-json-db');
const {Config} = require('node-json-db/dist/lib/JsonDBConfig');

const PORT = process.env.PORT || 5000;

// init DB
const db = new JsonDB(new Config('mydatabase', true, false, '/'));

const app = express();

app.use(express.json())

app.get("/api", (req,res) => {
  res.json({ message: "Welcome to the two factor authentication exmaple" })
});

// Register users & create temp secret
/*
當 user 發出 post request, server 產出一筆 secret 到 client 並且儲存在 DB
*/
app.post("/api/register", (req, res) => {

  const id = uuid.v4();
  try {
    const path = `/user/${id}`;
    // Create temporary secret until it it verified
    const temp_secret = speakeasy.generateSecret();
    // Create user in the database
    db.push(path, { id, temp_secret });
    // Send user id and base32 key to user
    res.json({ id, secret: temp_secret.base32 })
  } catch(e) {
    console.log(e);
    // 500 Internal Server Error 
    res.status(500).json({ message: 'Error generating secret key'})
  }
});

// Verify token and make secret to be checked
app.post("/api/verify", (req,res) => {

  // get from client
  // token comes from Authentication
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = db.getData(path);
    const { base32: secret } = user.temp_secret;

    // Verify process
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token
    });
    if (verified) {
      // Update user data (change temp_secret to secret)
      db.push(path, { id: userId, secret: user.temp_secret });
      res.json({ verified: true })
    } else {
      res.json({ verified: false})
    }
  } catch(error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user'})
  };
});

app.post("/api/validate", (req,res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = db.getData(path);
    console.log({ user })
    const { base32: secret } = user.secret;
    // Returns true if the token matches
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1 // 應該是允許的檢查次數
    });
    if (tokenValidates) {
      res.json({ validated: true })
    } else {
      res.json({ validated: false})
    }
  } catch(error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user'})
  };
})

app.listen(PORT, () => {
  console.log(`App is running on PORT: ${PORT}.`);
});