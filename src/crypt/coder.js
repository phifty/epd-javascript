/*global CryptoJS:false */

(function ($, $$, $$$) {
  "use strict";

  var _plainFromValue = function (value) {
        if (typeof(value.data) === "string") {
          return value.data.replace(/\n/g, "");
        } else {
          return value.data;
        }
      },
      _plainToValue = function (raw) {
        return { data: raw };
      },

      _hexFromValue = function (value) {
        return _toBase64(CryptoJS.enc.Hex.parse(value.data).words);
      },
      _hexToValue = function (raw) {
        var array = _fromBase64(raw);
        return {
          data: CryptoJS.enc.Hex.stringify(
                  CryptoJS.lib.WordArray.create(array))
        };
      },

      _base64FromValue = function (value) {
        return _toBase64(value.data);
      },
      _base64ToValue = function (raw) {
        return {
          data: _fromBase64(raw)
        };
      },

    _typeSettings = {
        rsaKey: {
          code: 0,
          fromValue: function (value) {
            return _toBase64(
                     _appendArray(
                       _appendArray([ ], value.modulus),
                       value.exponent));
          },
          toValue: function (raw) {
            var array = _fromBase64(raw);
            return {
              modulus: _shiftArray(array),
              exponent: _shiftArray(array)
            };
          }
        },
        rsaEncryptedData: {
          code: 1,
          fromValue: _plainFromValue,
          toValue: _plainToValue
        },
        rsaSignature: {
          code: 2,
          fromValue: _hexFromValue,
          toValue: _hexToValue
        },
        aesKey: {
          code: 3,
          fromValue: _base64FromValue,
          toValue: _base64ToValue
        },
        aesEncryptedData: {
          code: 4,
          fromValue: _plainFromValue,
          toValue: _plainToValue
        },
        salt: {
          code: 5,
          fromValue: _base64FromValue,
          toValue: _base64ToValue
        },
        rsaAesEncryptedData: {
          code: 6,
          fromValue: function (value) {
            var encryptedKey = $$$.encode(value.key),
                encryptedData = $$$.encode(value.data);
            return encryptedKey + "|" + encryptedData;
          },
          toValue: function (raw) {
            var encrypted = raw.split("|");
            return {
              key: $$$.decode(encrypted[0]),
              data: $$$.decode(encrypted[1])
            };
          }
        }
      },

      _appendArray = function (target, array) {
        if (typeof(array.length) === "undefined") {
          throw(new Error("Given parameter is not an array!"));
        }
        target.push(array.length);
        return target.concat(array);
      },

      _shiftArray = function (source) {
        var length = source.shift(),
            result = source.slice(0, length);
        source.splice(0, length);
        return result;
      },

      _typeByCode = function (code) {
        for (var type in _typeSettings) {
          if (_typeSettings.hasOwnProperty(type) && _typeSettings[type].code === code) {
            return type;
          }
        }
        return undefined;
      },

      _toCode = function (letter) {
        return CryptoJS.enc.Base64._map.indexOf(letter);
      },
      _fromCode = function (code) {
        return CryptoJS.enc.Base64._map[code];
      },

      _toBase64 = function (array) {
        return CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(array));
      },
      _fromBase64 = function (base64) {
        return CryptoJS.enc.Base64.parse(base64).words;
      };

  $$$.typeForLetter = function (letter) {
    return _typeByCode(_toCode(letter));
  };

  $$$.encode = function (value) {
    var typeSetting = _typeSettings[value.type];

    if (!typeSetting) {
      throw(new Error("Type " + value.type + " is not supported!"));
    }

    return _fromCode(typeSetting.code) + typeSetting.fromValue(value);
  };

  $$$.decode = function (encoded) {
    var code = _toCode(encoded[0])
      , type = _typeByCode(code)
      , value;

    if (!type) {
      throw(new Error("Type Nr. " + code + " is not supported!"));
    }

    value = _typeSettings[type].toValue(encoded.slice(1));
    value.type = type;
    return value;
  };

  $$$.ensureType = function (type, value) {
    if (!value || type !== value.type) {
      throw(new Error("The value " + JSON.stringify(value) + " need to be of type " + type + "!"));
    }
  };

  $$$.isEncoded = function (value) {
    return typeof value === "string";
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Coder = epdRoot.Crypt.Coder || { }));
