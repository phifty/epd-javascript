
(function ($, $$, $$$, $$$$) {
  "use strict";

  var // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
      pkcs1pad2 = function (s, n) {
        if (n < s.length + 11) { // TODO: fix for utf-8
          throw(new Error("Message too long for RSA"));
        }
        var ba = [ ];
        var i = s.length - 1;
        while (i >= 0 && n > 0) {
          var c = s.charCodeAt(i--);
          if(c < 128) { // encode using utf-8
            ba[--n] = c;
          } else if ((c > 127) && (c < 2048)) {
            ba[--n] = (c & 63) | 128;
            ba[--n] = (c >> 6) | 192;
          } else {
            ba[--n] = (c & 63) | 128;
            ba[--n] = ((c >> 6) & 63) | 128;
            ba[--n] = (c >> 12) | 224;
          }
        }
        ba[--n] = 0;
        var rng = new SecureRandom();
        var x = [ ];
        while (n > 2) { // random non-zero pad
          x[0] = 0;
          while (x[0] == 0) {
            rng.nextBytes(x);
          }
          ba[--n] = x[0];
        }
        ba[--n] = 2;
        ba[--n] = 0;
        return new BigInteger(ba);
      }

      // Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
    , pkcs1unpad2 = function (d, n) {
        var b = d.toByteArray();
        var i = 0;
        while (i < b.length && b[i] == 0) {
          ++i;
        }
        if (b.length - i != n - 1 || b[i] != 2) {
          return null;
        }
        ++i;
        while (b[i] != 0) {
          if (++i >= b.length) {
            return null;
          }
        }
        var ret = "";
        while (++i < b.length) {
          var c = b[i] & 255;
          if(c < 128) { // utf-8 decode
            ret += String.fromCharCode(c);
          } else if ((c > 191) && (c < 224)) {
            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
            ++i;
          } else {
            ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
            i += 2;
          }
        }
        return ret;
      };

  // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
  $$$$.encrypt = function (text, key) {
    var m = pkcs1pad2(text, (key.n.bitLength() + 7) >> 3);
    if (m == null) {
      return null;
    }
    var c = $$$$.doPublic(m, key);
    if (c == null) {
      return null;
    }
    var h = c.toString(16);
    if ((h.length & 1) == 0) {
      return h;
    } else {
      return "0" + h;
    }
  };

  // Return the PKCS#1 RSA decryption of "ctext".
  // "ctext" is an even-length hex string and the output is a plain string.
  $$$$.decrypt = function (cipherText, key) {
    var c = new BigInteger(cipherText, 16);
    var m = $$$$.doPrivate(c, key);
    if (m == null) {
      return null;
    }
    return pkcs1unpad2(m, (key.n.bitLength() + 7) >> 3);
  };

  // protected

  // Perform raw public operation on "x": return x^e (mod n)
  $$$$.doPublic = function (x, key) {
    return x.modPowInt(key.e, key.n);
  };

  // Perform raw private operation on "x": return x^d (mod n)
  $$$$.doPrivate = function (x, key) {
    if (key.p == null || key.q == null) {
      return x.modPow(key.d, key.n);
    }

    // TODO: re-calculate any missing CRT params
    var xp = x.mod(key.p).modPow(key.dmp1, key.p);
    var xq = x.mod(key.q).modPow(key.dmq1, key.q);

    while (xp.compareTo(xq) < 0) {
      xp = xp.add(key.p);
    }
    return xp.subtract(xq).multiply(key.coeff).mod(key.p).multiply(key.q).add(xq);
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { },
   epdRoot.Crypt.Asymmetric.RSA = epdRoot.Crypt.Asymmetric.RSA || { });
