
(function ($, $$) {
  "use strict";

  $$.keys = function (object) {
    var keys = [ ];
    $$.each(object, function (key) {
      keys.push(key);
    });
    return keys;
  };

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

  $$.map = function (array, handler) {
    var result = new Array(array.length);
    $$.each(array, function (index, value) {
      result[index] = handler(index, value);
    });
    return result;
  };

  $$.reduce = function (array, initialValue, handler) {
    var result = initialValue;
    this.each(array, function (index, item) {
      result = handler(result, item);
    });
    return result;
  };

  $$.include = function (array, value) {
    return !!$$.detect(array, function (index, item) {
      return item === value;
    });
  };

  $$.detect = function (arrayOrObject, handler) {
    if (!arrayOrObject) {
      return;
    }

    for (var index in arrayOrObject) {
      if (arrayOrObject.hasOwnProperty(index)) {
        var value = arrayOrObject[index];
        if (handler(index, value)) {
          return value;
        }
      }
    }

    return undefined;
  };

  $$.detectObjectWith = function(array, key, value) {
    return this.detect(array, function (index, object) {
      return object[key] === value;
    });
  };

  $$.select = function (array, handler) {
    var result = [ ];
    this.each(array, function (index, item) {
      if (handler(index, item)) {
        result.push(item);
      }
    });
    return result;
  };

  $$.selectObjectsWith = function (array, key, value) {
    return $$.select(array, function (index, object) {
      return object[key] === value;
    });
  };

  $$.selectNotNull = function (array) {
    return $$.select(array, function (index, value) {
      return !!value;
    });
  };

  $$.remove = function (array, item) {
    for (var index in array) {
      if (item === array[index]) {
        array.splice(index, 1);
      }
    }
  };

  $$.removeObjectsWith = function (array, key, value) {
    var results = [ ];
    for (var index in array) {
      if (array.hasOwnProperty(index)) {
        var object = array[index];
        if (object[key] === value) {
          array.splice(index, 1);
          results.push(object);
        }
      }
    }
    return results;
  };

  $$.count = function (array, handler) {
    var result = 0;
    this.each(array, function (index, item) {
      if (handler(index, item)) {
        result++;
      }
    });
    return result;
  };

  $$.countObjectsWith = function (array, key, value) {
    return this.count(array, function (index, object) {
      return object[key] === value;
    });
  };

  $$.compare = function (arrayOne, arrayTwo) {
    var result = arrayOne.length === arrayTwo.length;
    $$.each(arrayOne, function (index, item) {
      result = result && (item === arrayTwo[index]);
    });
    return result;
  };

  $$.without = function (arrayOne, arrayTwo) {
    var result = [ ];

    $$.each(arrayOne, function (index, item) {
      if (!$$.include(arrayTwo, item)) {
        result.push(item);
      }
    });

    return result;
  };

  $$.pair = function (array, handler) {
    var result = [ ];

    if (array.length === 1) {
      result.push(array[0]);
    } else if (array.length > 1) {
      var last = array[0];
      for (var index = 1; index < array.length; index++) {
        var current = array[index];
        result.push(handler(last, current));
        last = current;
      }
    }

    return result;
  };

}(epdRoot,
  epdRoot.Iterator = epdRoot.Iterator || { }));
