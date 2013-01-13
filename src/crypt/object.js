/*global CryptoJS:false */

(function ($, $$, $$$) {
  "use strict";

  $$$.generateId = function (length) {
    return CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(length || 16));
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Object = epdRoot.Crypt.Object || { });
