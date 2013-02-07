
(function ($, $$) {
  "use strict";

  $$.each = function (arrayOrObject, handler) {
    if (!arrayOrObject || arrayOrObject.length === 0) {
      return;
    }

    for (var index in arrayOrObject) {
      if (arrayOrObject.hasOwnProperty(index)) {
        handler(index, arrayOrObject[index]);
      }
    }
  };

}(epdRoot,
  epdRoot.Iterator = epdRoot.Iterator || { }));
