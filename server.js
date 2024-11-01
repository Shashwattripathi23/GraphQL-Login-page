const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLNonNull,
} = require("graphql");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = 3000;
const JWT_SECRET = "your_jwt_secret";

// MongoDB connection
mongoose.connect("mongodb://localhost:27017/logon", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  })
);

// GraphQL schema for login and signup
const schema = new GraphQLSchema({
  query: new GraphQLObjectType({
    name: "RootQueryType",
    fields: {
      hello: {
        type: GraphQLString,
        resolve: () => "Hello World!",
      },
    },
  }),
  mutation: new GraphQLObjectType({
    name: "RootMutationType",
    fields: {
      signup: {
        type: GraphQLString,
        args: {
          email: { type: new GraphQLNonNull(GraphQLString) },
          password: { type: new GraphQLNonNull(GraphQLString) },
        },
        resolve: async (_, { email, password }) => {
          const existingUser = await User.findOne({ email });
          if (existingUser) throw new Error("User already exists");

          const hashedPassword = await bcrypt.hash(password, 12);
          const newUser = new User({
            email,
            password: hashedPassword,
          });

          await newUser.save();
          return "User registered successfully";
        },
      },
      login: {
        type: new GraphQLObjectType({
          name: "AuthData",
          fields: {
            token: { type: GraphQLString },   
          },
        }),
        args: {
          email: { type: new GraphQLNonNull(GraphQLString) },
          password: { type: new GraphQLNonNull(GraphQLString) },
        },
        resolve: async (_, { email, password }) => {
          const user = await User.findOne({ email });
          if (!user) throw new Error("User not found");

          const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) throw new Error("Invalid credentials");

          const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
            expiresIn: "1h",
          });
          return { token };
        },
      },
    },
  }),
});

// Middleware for GraphQL endpoint
app.use(
  "/graphql",
  graphqlHTTP({
    schema,
    graphiql: true,
  })
);

app.use(express.json());
app.use(express.static("public"));

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// Basic route
app.get("/", (req, res) => res.send("Hello World!"));

// Start server
app.listen(port, () =>
  console.log(`Server running on http://localhost:${port}/graphql`)
);
