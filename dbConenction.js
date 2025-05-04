require('dotenv').config();

const mongoHost = process.env.MONGODB_HOST;
const mongoUser = process.env.MONGODB_USER;
const mongoPWD = process.env.MONGODB_PASSWORD;

const MongoClient = require("mongodb").MongoClient;

const atlasURI = `mongodb+srv://${mongoUser}:${mongoPWD}@${mongoHost}/?retryWrites=true`;

var database = new MongoClient(atlasURI, {});

module.exports = {database};