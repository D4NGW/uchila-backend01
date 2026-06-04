const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

app.use(cors());
app.use(express.json());

const CLIENT_ID = "33nZb90yOHPIJXVFbYG39";

app.post("/api/trocar-token", async (req,res)=>{

const { code, code_verifier, redirect_uri } = req.body;

try {

const response = await axios.post(
"https://auth.deriv.com/oauth2/token",
new URLSearchParams({
grant_type:"authorization_code",
code,
client_id:CLIENT_ID,
code_verifier,
redirect_uri
})
);

res.json({
access_token: response.data.access_token
});

} catch(err){
res.status(500).json({error:"falha auth"});
}

});

const PORT = process.env.PORT || 3001;
app.listen(PORT, ()=> console.log("Backend ON"));
