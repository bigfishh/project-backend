import express from 'express';
import bodyParser, { json } from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { Client } from 'pg';

const accessTokenSecret = "hello123"
const saltRounds = 10;
const client = new Client({
  host: "db-editor.cpiuuzm09nrd.us-east-1.rds.amazonaws.com",
  port: 5432,
  database: "editor",
  user: "postgres",
  password: "password"
});
client.connect();

const app = express();
app.use(cors());
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "http://localhost:8080"); 
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});
app.use(bodyParser.urlencoded({ extended: true }));

const PORT = 8000;
app.get('/', (req,res) => {
  res.json({
    message: "hello world"
  })
});

app.post('/signup', async(req, res) => {
  const { username, password } = req.body;
  let queryResult = await client.query(`SELECT * FROM users WHERE USERNAME = $$${username}$$;`);
  if (!queryResult.rows[0]) {
    bcrypt.hash(password, saltRounds, async(err, hash) => {
      const query = {
        text: "INSERT INTO users(username, password) VALUES($1, $2)",
        values: [username, hash]
      };
      await client.query(query);
      const accessToken = jwt.sign({ username: username }, accessTokenSecret);
      res.json({accessToken});
    });
  } else {
    res.json({message: "invalid username or password, please try again"})
  }
});

app.post('/login', async(req, res) => {
  const { username, password } = req.body;
  let queryResult = await client.query(`SELECT password, username FROM users WHERE USERNAME = $$${username}$$;`);
  let foundHashedPassword = queryResult.rows[0].password;
  bcrypt.compare(password, foundHashedPassword)
    .then((result) => {
      if (result) {
        const accessToken = jwt.sign({ username: queryResult.rows[0].username }, accessTokenSecret);
        res.json({accessToken});
      } else {
        res.json({message: "Username or password doesn't match"});
      }
    });
});


app.listen(PORT, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${PORT}`);
});



