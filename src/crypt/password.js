/*global CryptoJS:false */

(function ($, $$, $$$) {
  "use strict";

  var _settings = {
        saltSize: 16,
        keySize: 160/32,
        iterations: 1000
      };

  $$$.hash = function (password, parameters) {
    if (!password) {
      throw(new Error("no password given"));
    }
    parameters = parameters || { };

    var salt = parameters.salt || { type: "salt", data: CryptoJS.lib.WordArray.random(_settings.saltSize).words }
      , keySize = parameters.keySize || _settings.keySize
      , iterations = parameters.iterations || _settings.iterations
      , hash = {
          type: "aesKey",
          data: CryptoJS.PBKDF2(password, CryptoJS.lib.WordArray.create(salt.data), { keySize: keySize, iterations: iterations }).words
        };

    return {
      hash: hash,
      salt: salt,
      keySize: keySize,
      iterations: iterations
    };
  };

  $$$.benchmark = function (iterations) {
    var start = $.Time.current()
      , end;

    $$$.hash("sample", { iterations: iterations });
    end = $.Time.current();

    return end - start;
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Password = epdRoot.Crypt.Password || { }));
