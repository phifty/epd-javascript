/*global CryptoJS:false, RSAKey:false */

(function ($, $$, $$$) {
  "use strict";

  var _defaultKeyBits = 1024
    , _defaultPublicExponent = "00000003"

    , _joinArrays = function (arrays) {
        var result = [ ];
        $.Iterator.each(arrays, function (index, array) {
          result.push(array.length);
          result = result.concat(array);
        });
        return result;
      }

    , _splitArrays = function (array) {
        var results = [ ];
        for (var index = 0; index < array.length; ) {
          var length = array[index];
          index++;
          results.push(array.slice(index, index + length));
          index += length;
        }
        return results;
      }

    , _hexToBase64 = function (hex) {
        return _arrayToBase64(_hexToArray(hex));
      }
    , _base64ToHex = function (base64) {
        return _arrayToHex(_base64ToArray(base64));
      }
    , _arrayToBase64 = function (array) {
        return CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(array));
      }
    , _base64ToArray = function (base64) {
        return CryptoJS.enc.Base64.parse(base64).words;
      }
    , _hexToArray = function (hex) {
        return CryptoJS.enc.Hex.parse(hex).words;
      }
    , _arrayToHex = function (array) {
        return CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.create(array));
      };

  $$$.generateKeyPair = function (keyBits) {
    var rsa = new $$$.RSA.Key()
      , bits = keyBits || _defaultKeyBits
      , modulus, publicExponent, privateExponent;

    rsa.generate(bits, _defaultPublicExponent);

    modulus = _hexToArray(rsa.n.toString(16));
    publicExponent = _hexToArray(_defaultPublicExponent);
    privateExponent = _hexToArray(rsa.d.toString(16));

    return {
      publicKey: { type: "rsaKey", modulus: modulus, exponent: publicExponent },
      privateKey: { type: "rsaKey", modulus: modulus, exponent: privateExponent }
    };
  };

  $$$.encrypt = function (message, publicKey) {
    $$.Coder.ensureType("rsaKey", publicKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPublic(_arrayToHex(publicKey.modulus), _arrayToHex(publicKey.exponent));
    return { type: "rsaEncryptedData", data: $$$.RSA.encrypt(message, rsaKey) };
  };

  $$$.decrypt = function (encrypted, publicKey, privateKey) {
    $$.Coder.ensureType("rsaEncryptedData", encrypted);
    $$.Coder.ensureType("rsaKey", publicKey);
    $$.Coder.ensureType("rsaKey", privateKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPrivate(_arrayToHex(privateKey.modulus), _arrayToHex(publicKey.exponent), _arrayToHex(privateKey.exponent));
    return $$$.RSA.decrypt(encrypted.data, rsaKey);
  };

  $$$.encryptSymmetric = function (message, publicKey) {
    $$.Coder.ensureType("rsaKey", publicKey);

    var key = $$.Symmetric.generateKey()
      , encryptedKey = $$$.encrypt($$.Coder.encode(key), publicKey)
      , encryptedMessage = $$.Symmetric.encrypt(message, key);

    return { type: "rsaAesEncryptedData", key: encryptedKey, data: encryptedMessage };
  };

  $$$.decryptSymmetric = function (encrypted, publicKey, privateKey) {
    $$.Coder.ensureType("rsaAesEncryptedData", encrypted);
    $$.Coder.ensureType("rsaKey", publicKey);
    $$.Coder.ensureType("rsaKey", privateKey);

    var decryptedKey = $$.Coder.decode($$$.decrypt(encrypted.key, publicKey, privateKey));

    return $$.Symmetric.decrypt(encrypted.data, decryptedKey);
  };

  $$$.sign = function (message, publicKey, privateKey) {
    $$.Coder.ensureType("rsaKey", publicKey);
    $$.Coder.ensureType("rsaKey", privateKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPrivate(_arrayToHex(privateKey.modulus), _arrayToHex(publicKey.exponent), _arrayToHex(privateKey.exponent));
    return { type: "rsaSignature", data: $$$.RSA.Signer.signWithSHA256(message, rsaKey) };
  };

  $$$.verify = function (message, signature, publicKey) {
    $$.Coder.ensureType("rsaSignature", signature);
    $$.Coder.ensureType("rsaKey", publicKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPublic(_arrayToHex(publicKey.modulus), _arrayToHex(publicKey.exponent));
    return $$$.RSA.Signer.verify(message, rsaKey, signature.data);
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { });
