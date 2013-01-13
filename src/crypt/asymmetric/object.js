
(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.encrypt = function (object, publicKey) {
    return $$$.encryptSymmetric(JSON.stringify(object), publicKey);
  };

  $$$$.decrypt = function (encrypted, publicKey, privateKey) {
    return JSON.parse($$$.decryptSymmetric(encrypted, publicKey, privateKey));
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { },
  epdRoot.Crypt.Asymmetric.Object = epdRoot.Crypt.Asymmetric.Object || { }));
