
(function ($, $$) {
  "use strict";

  $$.keys = function (object) {
    var keys = [ ];
    $.Iterator.each(object, function (key) {
      keys.push(key);
    });
    return keys;
  };

  $$.clone = function (object) {
    if (!object) {
      return object;
    }

    var types = [ Number, String, Boolean ],
        result;

    $.Iterator.each(types, function (index, type) {
      if (object instanceof type) {
        result = type(object);
      }
    });

    if (typeof(result) === "undefined") {
      if (Object.prototype.toString.call(object) === "[object Array]") {
        result = [ ];
        $.Iterator.each(object, function (index, item) {
          result[index] = $$.clone(item);
        });
      } else if (typeof(object) === "object") {
        if (object.nodeType && typeof(object.cloneNode) === "function") {
          result = object.cloneNode(true);
        } else if (!object.prototype) {
          result = { };
          $.Iterator.each(object, function (key, value) {
            result[key] = $$.clone(value);
          });
        } else {
          result = object;
        }
      } else {
        result = object;
      }
    }

    return result;
  };

  $$.valueIn = function (object, dataPath) {
    return $.Collection.reduce(dataPath ? dataPath.split(".") : [ ], object, function (result, attribute) {
      return result ? result[attribute] : result;
    });
  };

  $$.stringify = function (object) {
    switch (typeof object) {
      case "number":
        return object.toString();
      case "string":
        return object;
      case "object":
        var keys = $$.keys(object);
        keys.sort();
        return $.Collection.reduce(keys, "", function (result, key) {
          var value = object[key];
          return result + (value === undefined ? "" : key + $$.stringify(value));
        });
      default:
        return "";
    }
  };

}(epdRoot,
  epdRoot.Object = epdRoot.Object || { }));
