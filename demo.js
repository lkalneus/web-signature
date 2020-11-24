// Helpers
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
function str2ab(str) {
  var buf = new ArrayBuffer(str.length); // 2 bytes for each char
  var bufView = new Uint8Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
function prettify(obj) {
    return JSON.stringify(obj, null, 4);
}
// Initial data
var order = {
      alias: "USD",
      name: "US dollars",
      type: "Fiat",
      deliveryDecimal: 0,
      comment: "US dollars",
      accountName: "Swedbank"
};

var order2 = {
      alias: "USD",
      name: "US dollars",
      type: "Fiat",
      deliveryDecimal: 5,
      comment: "US dollars",
      accountName: "Swedbank"
};

// Initial UI

function initUI() {
    document.getElementById("action-display").value = prettify(order);
}
initUI();
function display(str) {
    document.getElementById("console-display").value = str;
}


var storedKey;
var storedSignature;

// Key generation
function generateKey() {
    window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048, //can be 1024, 2048, or 4096
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
    )
    .then(function(key){
        //returns a keypair object
        console.log(key);
        storedKey = key;        
    });
}

function exportKey() {
    // exporting
    window.crypto.subtle.exportKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        storedKey.publicKey //can be a publicKey or privateKey, as long as extractable was true
    )
    .then(function(keydata){
        //returns the exported key data
        console.log(keydata);
        console.log("Exported key: ", btoa(JSON.stringify(keydata)));
        display("Exported key: \n"+btoa(JSON.stringify(keydata)));
    })
}

function sign(o) {
    window.crypto.subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 128, //the length of the salt
        },
        storedKey.privateKey, //from generateKey or importKey above
        str2ab(JSON.stringify(o)) //ArrayBuffer of data you want to sign
        )
        .then(function(signature){
            //returns an ArrayBuffer containing the signature
            storedSignature = signature;
            console.log(new Uint8Array(signature));
            console.log("Base64 representation of the signature: ", btoa(ab2str(signature)));
            display("Base64 representation of the signature: \n" + btoa(ab2str(signature)));
        });
}

function verify(o, signature) {
    window.crypto.subtle.verify(
    {
        name: "RSA-PSS",
        saltLength: 128, //the length of the salt
    },
    storedKey.publicKey, //from generateKey or importKey above
    signature, //ArrayBuffer of the signature
    str2ab(JSON.stringify(o)) //ArrayBuffer of the data
    )
    .then(function(isvalid){
        //returns a boolean on whether the signature is true or not
        console.log(isvalid);
        display(isvalid);
    })
    .catch(function(err){
        console.error(err);
    });
}

window.crypto.subtle.generateKey(
    {
        name: "RSA-PSS",
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //can be any combination of "sign" and "verify"
)
.then(function(key){
    //returns a keypair object
    console.log(key);
    storedKey = key;
    var data = str2ab(JSON.stringify(order));
    var data2 = str2ab(JSON.stringify(order2));

    window.crypto.subtle.sign(
    {
        name: "RSA-PSS",
        saltLength: 128, //the length of the salt
    },
    key.privateKey, //from generateKey or importKey above
    data //ArrayBuffer of data you want to sign
    )
    .then(function(signature){
        //returns an ArrayBuffer containing the signature
        console.log(new Uint8Array(signature));
        window.crypto.subtle.verify(
            {
                name: "RSA-PSS",
                saltLength: 128, //the length of the salt
            },
            key.publicKey, //from generateKey or importKey above
            signature, //ArrayBuffer of the signature
            data //ArrayBuffer of the data
            )
            .then(function(isvalid){
                //returns a boolean on whether the signature is true or not
                console.log(isvalid);
            })
            .catch(function(err){
                console.error(err);
            });
    })
    .catch(function(err){
        console.error(err);
    });
})
.catch(function(err){
    console.error(err);
});