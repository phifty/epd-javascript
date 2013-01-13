
(function ($, $$) {
  "use strict";

  $$.current = function () {
    return new Date().getTime();
  };

}(epdRoot,
  epdRoot.Time = epdRoot.Time || { }));
