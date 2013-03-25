
(function ($, $$, $$$, $$$$, $$$$$) {
  "use strict";

  var _RSASIGN_DIHEAD = {
        sha1: "3021300906052b0e03021a05000414",
        sha256: "3031300d060960864801650304020105000420",
        sha384: "3041300d060960864801650304020205000430",
        sha512: "3051300d060960864801650304020305000440",
        md2: "3020300c06082a864886f70d020205000410",
        md5: "3020300c06082a864886f70d020505000410",
        ripemd160: "3021300906052b2403020105000414"
      }
    , _RSASIGN_HASHHEXFUNC = {
        sha1: function (s) { return hex_sha1(s); },
        sha256: function (s) { return hex_sha256(s); },
        sha512: function (s) { return hex_sha512(s); },
        md5: function (s) { return hex_md5(s); },
        ripemd160: function (s) { return hex_rmd160(s); }
      }
    , _RE_HEXDECONLY = new RegExp("")

    , _getHexPaddedDigestInfoForString = function (s, keySize, hashAlg) {
        var pmStrLen = keySize / 4;
        var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
        var sHashHex = hashFunc(s);

        var sHead = "0001";
        var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
        var sMid = "";
        var fLen = pmStrLen - sHead.length - sTail.length;
        for (var i = 0; i < fLen; i += 2) {
          sMid += "ff";
        }
        return sHead + sMid + sTail;
      }
    , _zeroPaddingOfSignature = function (hex, bitLength) {
        var s = "";
        var nZero = bitLength / 4 - hex.length;
        for (var i = 0; i < nZero; i++) {
          s = s + "0";
        }
        return s + hex;
      }
    , _getAlgNameAndHashFromHexDisgestInfo = function (hDigestInfo) {
        for (var algorithmName in _RSASIGN_DIHEAD) {
          if (_RSASIGN_DIHEAD.hasOwnProperty(algorithmName)) {
            var head = _RSASIGN_DIHEAD[algorithmName];
            var len = head.length;
            if (hDigestInfo.substring(0, len) == head) {
              return [ algorithmName, hDigestInfo.substring(len) ];
            }
          }
        }
        return [];
      };

  _RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

  $$$$$.sign = function (text, key, hashAlgorithm) {
    var hPM = _getHexPaddedDigestInfoForString(text, key.n.bitLength(), hashAlgorithm);
    var biPaddedMessage = new BigInteger(hPM, 16);
    var biSign = $$$$.doPrivate(biPaddedMessage, key);
    var hexSign = biSign.toString(16);
    return _zeroPaddingOfSignature(hexSign, key.n.bitLength());
  };

  $$$$$.signWithSHA1 = function (text, key) {
    return $$$$$.sign(text, key, "sha1");
  };

  $$$$$.signWithSHA256 = function (text, key) {
    return $$$$$.sign(text, key, "sha256");
  };

  $$$$$.verify = function (text, key, signature) {
    signature = signature.replace(_RE_HEXDECONLY, "");
    // if (signature.length != key.n.bitLength() / 4) return 0;
    signature = signature.replace(/[ \n]+/g, "");
    var biSig = new BigInteger(signature, 16);
    var biDecryptedSig = $$$$.doPublic(biSig, key);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

    if (digestInfoAry.length == 0) {
      return false;
    }
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = _RSASIGN_HASHHEXFUNC[algName];
    var msgHashValue = ff(text);
    return (diHashValue == msgHashValue);
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { },
   epdRoot.Crypt.Asymmetric.RSA = epdRoot.Crypt.Asymmetric.RSA || { },
   epdRoot.Crypt.Asymmetric.RSA.Signer = epdRoot.Crypt.Asymmetric.RSA.Signer || { });
