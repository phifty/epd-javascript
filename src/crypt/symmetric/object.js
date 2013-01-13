
(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.encrypt = function (object, key) {
    return $$$.encrypt(JSON.stringify(object), key);
  };

  $$$$.decrypt = function (encrypted, key) {
    return JSON.parse($$$.decrypt(encrypted, key));
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Symmetric = epdRoot.Crypt.Symmetric || { },
  epdRoot.Crypt.Symmetric.Object = epdRoot.Crypt.Symmetric.Object || { }));
