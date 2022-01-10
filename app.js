require("dotenv").config();
require("./config/database").connect();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const express = require("express");
const auth = require("./middleware/auth");
const Admin = require("./model/admin");
var cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// REGISTER
app.post("/api/auth/register", async (req, res) => {

    try {
        // Get user input
        const {
            name,
            email,
            password
        } = req.body;

        // Validate user input
        if (!(name && email && password)) {
            return res.status(400).send("All input is required");
        }

        // check if user already exist
        // Validate if user exist in our database
        const oldUser = await Admin.findOne({
            email
        });

        if (oldUser) {
            return res.status(409).send("User Already Exist. Please Login");
        }

        // Create user in our database
        const admin = await Admin.create({
            name: name,
            email: email.toLowerCase(), // sanitize: convert email to lowercase
            password: await bcrypt.hash(password, 10),
        });

        // Create token
        const token = jwt.sign({
                admin_id: admin._id,
                email
            },
            process.env.TOKEN_KEY, {
                expiresIn: "2h",
            }
        );
        // save user token
        admin.token = token;

        // return new user
        res.status(201).json(admin);
    } catch (err) {
        console.log(err);
    }
    // Our register logic ends here
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {

    res.setHeader('Access-Control-Allow-Origin', 'localhost:4200');
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

    // Our login logic starts here
    try {
      // Get user input
      const { email, password } = req.body;
  
      // Validate user input
      if (!(email && password)) {
        res.status(400).send("All input is required");
      }
      // Validate if user exist in our database
      const admin = await Admin.findOne({ email });
  
      if (admin && (await bcrypt.compare(password, admin.password))) {
        // Create token
        const token = jwt.sign(
          { admin_id: admin._id, email },
          process.env.TOKEN_KEY,
          {
            expiresIn: "2h",
          }
        );
  
        // save user token
        admin.token = token;
  
        // user
        return res.status(200).json(admin);
      }
      return res.status(400).send("Invalid Credentials");
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
  });

  //protected routes
  app.get("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome 🙌 ");
  });

module.exports = app;