/*global CryptoJS:false */

(function ($, $$, $$$) {
  "use strict";

  var _keyLength = 16,
      _toBase64 = function (array) {
        return CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(array));
      };

  $$$.generateKey = function () {
    return {
      type: "aesKey",
      data: CryptoJS.lib.WordArray.random(_keyLength).words
    };
  };

  $$$.encrypt = function (message, key) {
    $.Crypt.Coder.ensureType("aesKey", key);

    return {
      type: "aesEncryptedData",
      data: CryptoJS.format.OpenSSL.stringify(
              CryptoJS.AES.encrypt(message, _toBase64(key.data)))
    };
  };

  $$$.decrypt = function (encrypted, key) {
    $.Crypt.Coder.ensureType("aesEncryptedData", encrypted);
    $.Crypt.Coder.ensureType("aesKey", key);

    return CryptoJS.enc.Utf8.stringify(
             CryptoJS.AES.decrypt(
               CryptoJS.format.OpenSSL.parse(encrypted.data), _toBase64(key.data)));
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Symmetric = epdRoot.Crypt.Symmetric || { });
