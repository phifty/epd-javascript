
(function ($, $$) {
  "use strict";

  $$.include = function (array, value) {
    return !!$$.detect(array, function (index, item) {
      return item === value;
    });
  };

  $$.map = function (array, handler) {
    var result = new Array(array.length);
    $.Iterator.each(array, function (index, value) {
      result[index] = handler(index, value);
    });
    return result;
  };

  $$.reduce = function (array, initialValue, handler) {
    var result = initialValue;
    $.Iterator.each(array, function (index, item) {
      result = handler(result, item);
    });
    return result;
  };

  $$.detect = function (array, handler) {
    if (!array) {
      return array;
    }

    for (var index in array) {
      if (array.hasOwnProperty(index)) {
        var value = array[index];
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
    $.Iterator.each(array, function (index, item) {
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

  $$.selectTruthy = function (array) {
    return $$.select(array, function (index, value) {
      return !!value;
    });
  };

  $$.remove = function (array, item) {
    for (var index in array) {
      if (array.hasOwnProperty(index) && item === array[index]) {
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

  $$.removeDuplicates = function (array, handler) {
    if (!array) {
      return array;
    }

    handler = handler || function (item, searchItem) {
      return item == searchItem;
    };

    for (var index = 0; index < array.length; index++) {
      var item = array[index];
      for (var searchIndex = index + 1; searchIndex < array.length; searchIndex++) {
        if (handler(item, array[searchIndex])) {
          array.splice(searchIndex, 1);
        }
      }
    }

    return array;
  };

  $$.compare = function (arrayOne, arrayTwo) {
    var result = arrayOne.length === arrayTwo.length;
    $.Iterator.each(arrayOne, function (index, item) {
      result = result && (item === arrayTwo[index]);
    });
    return result;
  };

  $$.without = function (arrayOne, arrayTwo) {
    var result = [ ];

    $.Iterator.each(arrayOne, function (index, item) {
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
  epdRoot.Collection = epdRoot.Collection || { }));
