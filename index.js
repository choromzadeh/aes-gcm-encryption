const express = require('express');
// const favicon = require('express-favicon');
const path = require('path');
const {encrypt,decrypt} =  require('./cryptoFunctions')





const port = process.env.PORT || 5050;

const app = express();
app.use(express.json());
// app.use(favicon(__dirname + '/build/favicon.ico'));
// the __dirname is the current directory from where the script is running
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'build')));
app.post('/encrypt', function (req, res) {
     
   
   try {
    const receivedData = req.body;
    const encryptResult =  encrypt(receivedData.plainText,receivedData.password,receivedData.AAD)
    res.send({
        encryptedText : encryptResult[0],
        tag : encryptResult[1]
    })

   } 
   
   catch (error) {
       res.status(400).send(error)
   } 
  
});

app.post('/decrypt', function (req, res) {
    const receivedData = req.body;
    const encryptResult =  decrypt(receivedData.encryptedText,receivedData.password,receivedData.tag)

    res.send({
        plainText : encryptResult[0],
        AAD : encryptResult[1]
    })
   });
app.get('/*', function (req, res) {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});
app.listen(port,()=>{
    console.log('app run on port: ' + port);
});


// const encData = encrypt('twwecdfad','3222ff','svsd4442')

// console.log(encData);
// console.log(decrypt('NBXm5Pl3JXQu7EE7Gk1/R4DjnP+3meif6rELf52vzz03GPFZDCIetQlaVdYFtMcGxBfDpgbPd6PFdXgEAh5VyOAPV8KncqnRvUKCjMAm/PNzdnNkNDQ0Mm/5IvIrrtwMEg==',
//                     '3222ff',
//                     'pA27pf+2XC5Wf94CyadB7g==') 
//                     );