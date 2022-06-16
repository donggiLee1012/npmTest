// import sha256 from "crypto-js/sha256";
// import hmacSHA256 from "crypto-js/hmac-sha512";
// import Base64 from "crypto-js/enc-base64"

var AES = require("crypto-js/aes");
var SHA256 = require("crypto-js/sha256");
var CryptoJS = require("crypto-js")

// console.log(SHA256("Message"));
// console.log(CryptoJS.HmacSHA1("Message","Key"));


var encrypted = CryptoJS.AES.encrypt("TEST","KEY1");
// var decrypted = CryptoJS.AES.decrypt(encrypted);
console.log(encrypted.ciphertext.toString());