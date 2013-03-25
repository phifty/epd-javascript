
(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.Key = function () {
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
  };

  // Generate a new random private key B bits long, using public expt E
  $$$$.Key.prototype.generate = function (B, E) {
    var rng = new SecureRandom();
    var qs = B >> 1;
    this.e = parseInt(E, 16);
    var ee = new BigInteger(E, 16);
    for (;;) {
      for (;;) {
        this.p = new BigInteger(B - qs, 1, rng);
        if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) {
          break;
        }
      }
      for (;;) {
        this.q = new BigInteger(qs, 1, rng);
        if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) {
          break;
        }
      }
      if (this.p.compareTo(this.q) <= 0) {
        var t = this.p;
        this.p = this.q;
        this.q = t;
      }
      var p1 = this.p.subtract(BigInteger.ONE);
      var q1 = this.q.subtract(BigInteger.ONE);
      var phi = p1.multiply(q1);
      if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
        this.n = this.p.multiply(this.q);
        this.d = ee.modInverse(phi);
        this.dmp1 = this.d.mod(p1);
        this.dmq1 = this.d.mod(q1);
        this.coeff = this.q.modInverse(this.p);
        break;
      }
    }
  };

  // Set the public key fields N and e from hex strings
  $$$$.Key.prototype.setPublic = function (N, E) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
      this.n = new BigInteger(N, 16);
      this.e = parseInt(E, 16);
    } else {
      throw(new Error("Invalid RSA public key"));
    }
  };

  // Set the private key fields N, e, and d from hex strings
  $$$$.Key.prototype.setPrivate = function (N, E, D) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
      this.n = new BigInteger(N, 16);
      this.e = parseInt(E, 16);
      this.d = new BigInteger(D, 16);
    } else {
      throw(new Error("Invalid RSA private key"));
    }
  };

  // Set the private key fields N, e, d and CRT params from hex strings
  $$$$.Key.prototype.setPrivateEx = function (N, E, D, P, Q, DP, DQ, C) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
      this.n = new BigInteger(N, 16);
      this.e = parseInt(E, 16);
      this.d = new BigInteger(D, 16);
      this.p = new BigInteger(P, 16);
      this.q = new BigInteger(Q, 16);
      this.dmp1 = new BigInteger(DP, 16);
      this.dmq1 = new BigInteger(DQ, 16);
      this.coeff = new BigInteger(C, 16);
    } else {
      throw(new Error("Invalid RSA private key"));
    }
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { },
   epdRoot.Crypt.Asymmetric.RSA = epdRoot.Crypt.Asymmetric.RSA || { });
