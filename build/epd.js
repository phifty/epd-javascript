// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
;
// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
  rng_pool[rng_pptr++] ^= x & 255;
  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
  rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
  rng_pool = new Array();
  rng_pptr = 0;
  var t;
  if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
    // Extract entropy (256 bits) from NS4 RNG if available
    var z = window.crypto.random(32);
    for(t = 0; t < z.length; ++t)
      rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
  }
  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random());
    rng_pool[rng_pptr++] = t >>> 8;
    rng_pool[rng_pptr++] = t & 255;
  }
  rng_pptr = 0;
  rng_seed_time();
  //rng_seed_int(window.screenX);
  //rng_seed_int(window.screenY);
}

function rng_get_byte() {
  if(rng_state == null) {
    rng_seed_time();
    rng_state = prng_newstate();
    rng_state.init(rng_pool);
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
    //rng_pool = null;
  }
  // TODO: allow reseeding after first request
  return rng_state.next();
}

function rng_get_bytes(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;
// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

var CryptoJS=CryptoJS||function(s,p){var m={},l=m.lib={},n=function(){},r=l.Base={extend:function(b){n.prototype=this;var h=new n;b&&h.mixIn(b);h.hasOwnProperty("init")||(h.init=function(){h.$super.init.apply(this,arguments)});h.init.prototype=h;h.$super=this;return h},create:function(){var b=this.extend();b.init.apply(b,arguments);return b},init:function(){},mixIn:function(b){for(var h in b)b.hasOwnProperty(h)&&(this[h]=b[h]);b.hasOwnProperty("toString")&&(this.toString=b.toString)},clone:function(){return this.init.prototype.extend(this)}},
q=l.WordArray=r.extend({init:function(b,h){b=this.words=b||[];this.sigBytes=h!=p?h:4*b.length},toString:function(b){return(b||t).stringify(this)},concat:function(b){var h=this.words,a=b.words,j=this.sigBytes;b=b.sigBytes;this.clamp();if(j%4)for(var g=0;g<b;g++)h[j+g>>>2]|=(a[g>>>2]>>>24-8*(g%4)&255)<<24-8*((j+g)%4);else if(65535<a.length)for(g=0;g<b;g+=4)h[j+g>>>2]=a[g>>>2];else h.push.apply(h,a);this.sigBytes+=b;return this},clamp:function(){var b=this.words,h=this.sigBytes;b[h>>>2]&=4294967295<<
32-8*(h%4);b.length=s.ceil(h/4)},clone:function(){var b=r.clone.call(this);b.words=this.words.slice(0);return b},random:function(b){for(var h=[],a=0;a<b;a+=4)h.push(4294967296*s.random()|0);return new q.init(h,b)}}),v=m.enc={},t=v.Hex={stringify:function(b){var a=b.words;b=b.sigBytes;for(var g=[],j=0;j<b;j++){var k=a[j>>>2]>>>24-8*(j%4)&255;g.push((k>>>4).toString(16));g.push((k&15).toString(16))}return g.join("")},parse:function(b){for(var a=b.length,g=[],j=0;j<a;j+=2)g[j>>>3]|=parseInt(b.substr(j,
2),16)<<24-4*(j%8);return new q.init(g,a/2)}},a=v.Latin1={stringify:function(b){var a=b.words;b=b.sigBytes;for(var g=[],j=0;j<b;j++)g.push(String.fromCharCode(a[j>>>2]>>>24-8*(j%4)&255));return g.join("")},parse:function(b){for(var a=b.length,g=[],j=0;j<a;j++)g[j>>>2]|=(b.charCodeAt(j)&255)<<24-8*(j%4);return new q.init(g,a)}},u=v.Utf8={stringify:function(b){try{return decodeURIComponent(escape(a.stringify(b)))}catch(g){throw Error("Malformed UTF-8 data");}},parse:function(b){return a.parse(unescape(encodeURIComponent(b)))}},
g=l.BufferedBlockAlgorithm=r.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(b){"string"==typeof b&&(b=u.parse(b));this._data.concat(b);this._nDataBytes+=b.sigBytes},_process:function(b){var a=this._data,g=a.words,j=a.sigBytes,k=this.blockSize,m=j/(4*k),m=b?s.ceil(m):s.max((m|0)-this._minBufferSize,0);b=m*k;j=s.min(4*b,j);if(b){for(var l=0;l<b;l+=k)this._doProcessBlock(g,l);l=g.splice(0,b);a.sigBytes-=j}return new q.init(l,j)},clone:function(){var b=r.clone.call(this);
b._data=this._data.clone();return b},_minBufferSize:0});l.Hasher=g.extend({cfg:r.extend(),init:function(b){this.cfg=this.cfg.extend(b);this.reset()},reset:function(){g.reset.call(this);this._doReset()},update:function(b){this._append(b);this._process();return this},finalize:function(b){b&&this._append(b);return this._doFinalize()},blockSize:16,_createHelper:function(b){return function(a,g){return(new b.init(g)).finalize(a)}},_createHmacHelper:function(b){return function(a,g){return(new k.HMAC.init(b,
g)).finalize(a)}}});var k=m.algo={};return m}(Math);
(function(s){function p(a,k,b,h,l,j,m){a=a+(k&b|~k&h)+l+m;return(a<<j|a>>>32-j)+k}function m(a,k,b,h,l,j,m){a=a+(k&h|b&~h)+l+m;return(a<<j|a>>>32-j)+k}function l(a,k,b,h,l,j,m){a=a+(k^b^h)+l+m;return(a<<j|a>>>32-j)+k}function n(a,k,b,h,l,j,m){a=a+(b^(k|~h))+l+m;return(a<<j|a>>>32-j)+k}for(var r=CryptoJS,q=r.lib,v=q.WordArray,t=q.Hasher,q=r.algo,a=[],u=0;64>u;u++)a[u]=4294967296*s.abs(s.sin(u+1))|0;q=q.MD5=t.extend({_doReset:function(){this._hash=new v.init([1732584193,4023233417,2562383102,271733878])},
_doProcessBlock:function(g,k){for(var b=0;16>b;b++){var h=k+b,w=g[h];g[h]=(w<<8|w>>>24)&16711935|(w<<24|w>>>8)&4278255360}var b=this._hash.words,h=g[k+0],w=g[k+1],j=g[k+2],q=g[k+3],r=g[k+4],s=g[k+5],t=g[k+6],u=g[k+7],v=g[k+8],x=g[k+9],y=g[k+10],z=g[k+11],A=g[k+12],B=g[k+13],C=g[k+14],D=g[k+15],c=b[0],d=b[1],e=b[2],f=b[3],c=p(c,d,e,f,h,7,a[0]),f=p(f,c,d,e,w,12,a[1]),e=p(e,f,c,d,j,17,a[2]),d=p(d,e,f,c,q,22,a[3]),c=p(c,d,e,f,r,7,a[4]),f=p(f,c,d,e,s,12,a[5]),e=p(e,f,c,d,t,17,a[6]),d=p(d,e,f,c,u,22,a[7]),
c=p(c,d,e,f,v,7,a[8]),f=p(f,c,d,e,x,12,a[9]),e=p(e,f,c,d,y,17,a[10]),d=p(d,e,f,c,z,22,a[11]),c=p(c,d,e,f,A,7,a[12]),f=p(f,c,d,e,B,12,a[13]),e=p(e,f,c,d,C,17,a[14]),d=p(d,e,f,c,D,22,a[15]),c=m(c,d,e,f,w,5,a[16]),f=m(f,c,d,e,t,9,a[17]),e=m(e,f,c,d,z,14,a[18]),d=m(d,e,f,c,h,20,a[19]),c=m(c,d,e,f,s,5,a[20]),f=m(f,c,d,e,y,9,a[21]),e=m(e,f,c,d,D,14,a[22]),d=m(d,e,f,c,r,20,a[23]),c=m(c,d,e,f,x,5,a[24]),f=m(f,c,d,e,C,9,a[25]),e=m(e,f,c,d,q,14,a[26]),d=m(d,e,f,c,v,20,a[27]),c=m(c,d,e,f,B,5,a[28]),f=m(f,c,
d,e,j,9,a[29]),e=m(e,f,c,d,u,14,a[30]),d=m(d,e,f,c,A,20,a[31]),c=l(c,d,e,f,s,4,a[32]),f=l(f,c,d,e,v,11,a[33]),e=l(e,f,c,d,z,16,a[34]),d=l(d,e,f,c,C,23,a[35]),c=l(c,d,e,f,w,4,a[36]),f=l(f,c,d,e,r,11,a[37]),e=l(e,f,c,d,u,16,a[38]),d=l(d,e,f,c,y,23,a[39]),c=l(c,d,e,f,B,4,a[40]),f=l(f,c,d,e,h,11,a[41]),e=l(e,f,c,d,q,16,a[42]),d=l(d,e,f,c,t,23,a[43]),c=l(c,d,e,f,x,4,a[44]),f=l(f,c,d,e,A,11,a[45]),e=l(e,f,c,d,D,16,a[46]),d=l(d,e,f,c,j,23,a[47]),c=n(c,d,e,f,h,6,a[48]),f=n(f,c,d,e,u,10,a[49]),e=n(e,f,c,d,
C,15,a[50]),d=n(d,e,f,c,s,21,a[51]),c=n(c,d,e,f,A,6,a[52]),f=n(f,c,d,e,q,10,a[53]),e=n(e,f,c,d,y,15,a[54]),d=n(d,e,f,c,w,21,a[55]),c=n(c,d,e,f,v,6,a[56]),f=n(f,c,d,e,D,10,a[57]),e=n(e,f,c,d,t,15,a[58]),d=n(d,e,f,c,B,21,a[59]),c=n(c,d,e,f,r,6,a[60]),f=n(f,c,d,e,z,10,a[61]),e=n(e,f,c,d,j,15,a[62]),d=n(d,e,f,c,x,21,a[63]);b[0]=b[0]+c|0;b[1]=b[1]+d|0;b[2]=b[2]+e|0;b[3]=b[3]+f|0},_doFinalize:function(){var a=this._data,k=a.words,b=8*this._nDataBytes,h=8*a.sigBytes;k[h>>>5]|=128<<24-h%32;var l=s.floor(b/
4294967296);k[(h+64>>>9<<4)+15]=(l<<8|l>>>24)&16711935|(l<<24|l>>>8)&4278255360;k[(h+64>>>9<<4)+14]=(b<<8|b>>>24)&16711935|(b<<24|b>>>8)&4278255360;a.sigBytes=4*(k.length+1);this._process();a=this._hash;k=a.words;for(b=0;4>b;b++)h=k[b],k[b]=(h<<8|h>>>24)&16711935|(h<<24|h>>>8)&4278255360;return a},clone:function(){var a=t.clone.call(this);a._hash=this._hash.clone();return a}});r.MD5=t._createHelper(q);r.HmacMD5=t._createHmacHelper(q)})(Math);
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

var CryptoJS=CryptoJS||function(u,p){var d={},l=d.lib={},s=function(){},t=l.Base={extend:function(a){s.prototype=this;var c=new s;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=l.WordArray=t.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=p?c:4*a.length},toString:function(a){return(a||v).stringify(this)},concat:function(a){var c=this.words,e=a.words,j=this.sigBytes;a=a.sigBytes;this.clamp();if(j%4)for(var k=0;k<a;k++)c[j+k>>>2]|=(e[k>>>2]>>>24-8*(k%4)&255)<<24-8*((j+k)%4);else if(65535<e.length)for(k=0;k<a;k+=4)c[j+k>>>2]=e[k>>>2];else c.push.apply(c,e);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=u.ceil(c/4)},clone:function(){var a=t.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],e=0;e<a;e+=4)c.push(4294967296*u.random()|0);return new r.init(c,a)}}),w=d.enc={},v=w.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var e=[],j=0;j<a;j++){var k=c[j>>>2]>>>24-8*(j%4)&255;e.push((k>>>4).toString(16));e.push((k&15).toString(16))}return e.join("")},parse:function(a){for(var c=a.length,e=[],j=0;j<c;j+=2)e[j>>>3]|=parseInt(a.substr(j,
2),16)<<24-4*(j%8);return new r.init(e,c/2)}},b=w.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var e=[],j=0;j<a;j++)e.push(String.fromCharCode(c[j>>>2]>>>24-8*(j%4)&255));return e.join("")},parse:function(a){for(var c=a.length,e=[],j=0;j<c;j++)e[j>>>2]|=(a.charCodeAt(j)&255)<<24-8*(j%4);return new r.init(e,c)}},x=w.Utf8={stringify:function(a){try{return decodeURIComponent(escape(b.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return b.parse(unescape(encodeURIComponent(a)))}},
q=l.BufferedBlockAlgorithm=t.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=x.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,e=c.words,j=c.sigBytes,k=this.blockSize,b=j/(4*k),b=a?u.ceil(b):u.max((b|0)-this._minBufferSize,0);a=b*k;j=u.min(4*a,j);if(a){for(var q=0;q<a;q+=k)this._doProcessBlock(e,q);q=e.splice(0,a);c.sigBytes-=j}return new r.init(q,j)},clone:function(){var a=t.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});l.Hasher=q.extend({cfg:t.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){q.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,e){return(new a.init(e)).finalize(b)}},_createHmacHelper:function(a){return function(b,e){return(new n.HMAC.init(a,
e)).finalize(b)}}});var n=d.algo={};return d}(Math);
(function(){var u=CryptoJS,p=u.lib.WordArray;u.enc.Base64={stringify:function(d){var l=d.words,p=d.sigBytes,t=this._map;d.clamp();d=[];for(var r=0;r<p;r+=3)for(var w=(l[r>>>2]>>>24-8*(r%4)&255)<<16|(l[r+1>>>2]>>>24-8*((r+1)%4)&255)<<8|l[r+2>>>2]>>>24-8*((r+2)%4)&255,v=0;4>v&&r+0.75*v<p;v++)d.push(t.charAt(w>>>6*(3-v)&63));if(l=t.charAt(64))for(;d.length%4;)d.push(l);return d.join("")},parse:function(d){var l=d.length,s=this._map,t=s.charAt(64);t&&(t=d.indexOf(t),-1!=t&&(l=t));for(var t=[],r=0,w=0;w<
l;w++)if(w%4){var v=s.indexOf(d.charAt(w-1))<<2*(w%4),b=s.indexOf(d.charAt(w))>>>6-2*(w%4);t[r>>>2]|=(v|b)<<24-8*(r%4);r++}return p.create(t,r)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();
(function(u){function p(b,n,a,c,e,j,k){b=b+(n&a|~n&c)+e+k;return(b<<j|b>>>32-j)+n}function d(b,n,a,c,e,j,k){b=b+(n&c|a&~c)+e+k;return(b<<j|b>>>32-j)+n}function l(b,n,a,c,e,j,k){b=b+(n^a^c)+e+k;return(b<<j|b>>>32-j)+n}function s(b,n,a,c,e,j,k){b=b+(a^(n|~c))+e+k;return(b<<j|b>>>32-j)+n}for(var t=CryptoJS,r=t.lib,w=r.WordArray,v=r.Hasher,r=t.algo,b=[],x=0;64>x;x++)b[x]=4294967296*u.abs(u.sin(x+1))|0;r=r.MD5=v.extend({_doReset:function(){this._hash=new w.init([1732584193,4023233417,2562383102,271733878])},
_doProcessBlock:function(q,n){for(var a=0;16>a;a++){var c=n+a,e=q[c];q[c]=(e<<8|e>>>24)&16711935|(e<<24|e>>>8)&4278255360}var a=this._hash.words,c=q[n+0],e=q[n+1],j=q[n+2],k=q[n+3],z=q[n+4],r=q[n+5],t=q[n+6],w=q[n+7],v=q[n+8],A=q[n+9],B=q[n+10],C=q[n+11],u=q[n+12],D=q[n+13],E=q[n+14],x=q[n+15],f=a[0],m=a[1],g=a[2],h=a[3],f=p(f,m,g,h,c,7,b[0]),h=p(h,f,m,g,e,12,b[1]),g=p(g,h,f,m,j,17,b[2]),m=p(m,g,h,f,k,22,b[3]),f=p(f,m,g,h,z,7,b[4]),h=p(h,f,m,g,r,12,b[5]),g=p(g,h,f,m,t,17,b[6]),m=p(m,g,h,f,w,22,b[7]),
f=p(f,m,g,h,v,7,b[8]),h=p(h,f,m,g,A,12,b[9]),g=p(g,h,f,m,B,17,b[10]),m=p(m,g,h,f,C,22,b[11]),f=p(f,m,g,h,u,7,b[12]),h=p(h,f,m,g,D,12,b[13]),g=p(g,h,f,m,E,17,b[14]),m=p(m,g,h,f,x,22,b[15]),f=d(f,m,g,h,e,5,b[16]),h=d(h,f,m,g,t,9,b[17]),g=d(g,h,f,m,C,14,b[18]),m=d(m,g,h,f,c,20,b[19]),f=d(f,m,g,h,r,5,b[20]),h=d(h,f,m,g,B,9,b[21]),g=d(g,h,f,m,x,14,b[22]),m=d(m,g,h,f,z,20,b[23]),f=d(f,m,g,h,A,5,b[24]),h=d(h,f,m,g,E,9,b[25]),g=d(g,h,f,m,k,14,b[26]),m=d(m,g,h,f,v,20,b[27]),f=d(f,m,g,h,D,5,b[28]),h=d(h,f,
m,g,j,9,b[29]),g=d(g,h,f,m,w,14,b[30]),m=d(m,g,h,f,u,20,b[31]),f=l(f,m,g,h,r,4,b[32]),h=l(h,f,m,g,v,11,b[33]),g=l(g,h,f,m,C,16,b[34]),m=l(m,g,h,f,E,23,b[35]),f=l(f,m,g,h,e,4,b[36]),h=l(h,f,m,g,z,11,b[37]),g=l(g,h,f,m,w,16,b[38]),m=l(m,g,h,f,B,23,b[39]),f=l(f,m,g,h,D,4,b[40]),h=l(h,f,m,g,c,11,b[41]),g=l(g,h,f,m,k,16,b[42]),m=l(m,g,h,f,t,23,b[43]),f=l(f,m,g,h,A,4,b[44]),h=l(h,f,m,g,u,11,b[45]),g=l(g,h,f,m,x,16,b[46]),m=l(m,g,h,f,j,23,b[47]),f=s(f,m,g,h,c,6,b[48]),h=s(h,f,m,g,w,10,b[49]),g=s(g,h,f,m,
E,15,b[50]),m=s(m,g,h,f,r,21,b[51]),f=s(f,m,g,h,u,6,b[52]),h=s(h,f,m,g,k,10,b[53]),g=s(g,h,f,m,B,15,b[54]),m=s(m,g,h,f,e,21,b[55]),f=s(f,m,g,h,v,6,b[56]),h=s(h,f,m,g,x,10,b[57]),g=s(g,h,f,m,t,15,b[58]),m=s(m,g,h,f,D,21,b[59]),f=s(f,m,g,h,z,6,b[60]),h=s(h,f,m,g,C,10,b[61]),g=s(g,h,f,m,j,15,b[62]),m=s(m,g,h,f,A,21,b[63]);a[0]=a[0]+f|0;a[1]=a[1]+m|0;a[2]=a[2]+g|0;a[3]=a[3]+h|0},_doFinalize:function(){var b=this._data,n=b.words,a=8*this._nDataBytes,c=8*b.sigBytes;n[c>>>5]|=128<<24-c%32;var e=u.floor(a/
4294967296);n[(c+64>>>9<<4)+15]=(e<<8|e>>>24)&16711935|(e<<24|e>>>8)&4278255360;n[(c+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(n.length+1);this._process();b=this._hash;n=b.words;for(a=0;4>a;a++)c=n[a],n[a]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360;return b},clone:function(){var b=v.clone.call(this);b._hash=this._hash.clone();return b}});t.MD5=v._createHelper(r);t.HmacMD5=v._createHmacHelper(r)})(Math);
(function(){var u=CryptoJS,p=u.lib,d=p.Base,l=p.WordArray,p=u.algo,s=p.EvpKDF=d.extend({cfg:d.extend({keySize:4,hasher:p.MD5,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(d,r){for(var p=this.cfg,s=p.hasher.create(),b=l.create(),u=b.words,q=p.keySize,p=p.iterations;u.length<q;){n&&s.update(n);var n=s.update(d).finalize(r);s.reset();for(var a=1;a<p;a++)n=s.finalize(n),s.reset();b.concat(n)}b.sigBytes=4*q;return b}});u.EvpKDF=function(d,l,p){return s.create(p).compute(d,
l)}})();
CryptoJS.lib.Cipher||function(u){var p=CryptoJS,d=p.lib,l=d.Base,s=d.WordArray,t=d.BufferedBlockAlgorithm,r=p.enc.Base64,w=p.algo.EvpKDF,v=d.Cipher=t.extend({cfg:l.extend(),createEncryptor:function(e,a){return this.create(this._ENC_XFORM_MODE,e,a)},createDecryptor:function(e,a){return this.create(this._DEC_XFORM_MODE,e,a)},init:function(e,a,b){this.cfg=this.cfg.extend(b);this._xformMode=e;this._key=a;this.reset()},reset:function(){t.reset.call(this);this._doReset()},process:function(e){this._append(e);return this._process()},
finalize:function(e){e&&this._append(e);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(e){return{encrypt:function(b,k,d){return("string"==typeof k?c:a).encrypt(e,b,k,d)},decrypt:function(b,k,d){return("string"==typeof k?c:a).decrypt(e,b,k,d)}}}});d.StreamCipher=v.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var b=p.mode={},x=function(e,a,b){var c=this._iv;c?this._iv=u:c=this._prevBlock;for(var d=0;d<b;d++)e[a+d]^=
c[d]},q=(d.BlockCipherMode=l.extend({createEncryptor:function(e,a){return this.Encryptor.create(e,a)},createDecryptor:function(e,a){return this.Decryptor.create(e,a)},init:function(e,a){this._cipher=e;this._iv=a}})).extend();q.Encryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize;x.call(this,e,a,c);b.encryptBlock(e,a);this._prevBlock=e.slice(a,a+c)}});q.Decryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize,d=e.slice(a,a+c);b.decryptBlock(e,a);x.call(this,
e,a,c);this._prevBlock=d}});b=b.CBC=q;q=(p.pad={}).Pkcs7={pad:function(a,b){for(var c=4*b,c=c-a.sigBytes%c,d=c<<24|c<<16|c<<8|c,l=[],n=0;n<c;n+=4)l.push(d);c=s.create(l,c);a.concat(c)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};d.BlockCipher=v.extend({cfg:v.cfg.extend({mode:b,padding:q}),reset:function(){v.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var c=a.createEncryptor;else c=a.createDecryptor,this._minBufferSize=1;this._mode=c.call(a,
this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var n=d.CipherParams=l.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),b=(p.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext;a=a.salt;return(a?s.create([1398893684,
1701076831]).concat(a).concat(b):b).toString(r)},parse:function(a){a=r.parse(a);var b=a.words;if(1398893684==b[0]&&1701076831==b[1]){var c=s.create(b.slice(2,4));b.splice(0,4);a.sigBytes-=16}return n.create({ciphertext:a,salt:c})}},a=d.SerializableCipher=l.extend({cfg:l.extend({format:b}),encrypt:function(a,b,c,d){d=this.cfg.extend(d);var l=a.createEncryptor(c,d);b=l.finalize(b);l=l.cfg;return n.create({ciphertext:b,key:c,iv:l.iv,algorithm:a,mode:l.mode,padding:l.padding,blockSize:a.blockSize,formatter:d.format})},
decrypt:function(a,b,c,d){d=this.cfg.extend(d);b=this._parse(b,d.format);return a.createDecryptor(c,d).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a,this):a}}),p=(p.kdf={}).OpenSSL={execute:function(a,b,c,d){d||(d=s.random(8));a=w.create({keySize:b+c}).compute(a,d);c=s.create(a.words.slice(b),4*c);a.sigBytes=4*b;return n.create({key:a,iv:c,salt:d})}},c=d.PasswordBasedCipher=a.extend({cfg:a.cfg.extend({kdf:p}),encrypt:function(b,c,d,l){l=this.cfg.extend(l);d=l.kdf.execute(d,
b.keySize,b.ivSize);l.iv=d.iv;b=a.encrypt.call(this,b,c,d.key,l);b.mixIn(d);return b},decrypt:function(b,c,d,l){l=this.cfg.extend(l);c=this._parse(c,l.format);d=l.kdf.execute(d,b.keySize,b.ivSize,c.salt);l.iv=d.iv;return a.decrypt.call(this,b,c,d.key,l)}})}();
(function(){for(var u=CryptoJS,p=u.lib.BlockCipher,d=u.algo,l=[],s=[],t=[],r=[],w=[],v=[],b=[],x=[],q=[],n=[],a=[],c=0;256>c;c++)a[c]=128>c?c<<1:c<<1^283;for(var e=0,j=0,c=0;256>c;c++){var k=j^j<<1^j<<2^j<<3^j<<4,k=k>>>8^k&255^99;l[e]=k;s[k]=e;var z=a[e],F=a[z],G=a[F],y=257*a[k]^16843008*k;t[e]=y<<24|y>>>8;r[e]=y<<16|y>>>16;w[e]=y<<8|y>>>24;v[e]=y;y=16843009*G^65537*F^257*z^16843008*e;b[k]=y<<24|y>>>8;x[k]=y<<16|y>>>16;q[k]=y<<8|y>>>24;n[k]=y;e?(e=z^a[a[a[G^z]]],j^=a[a[j]]):e=j=1}var H=[0,1,2,4,8,
16,32,64,128,27,54],d=d.AES=p.extend({_doReset:function(){for(var a=this._key,c=a.words,d=a.sigBytes/4,a=4*((this._nRounds=d+6)+1),e=this._keySchedule=[],j=0;j<a;j++)if(j<d)e[j]=c[j];else{var k=e[j-1];j%d?6<d&&4==j%d&&(k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255]):(k=k<<8|k>>>24,k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255],k^=H[j/d|0]<<24);e[j]=e[j-d]^k}c=this._invKeySchedule=[];for(d=0;d<a;d++)j=a-d,k=d%4?e[j]:e[j-4],c[d]=4>d||4>=j?k:b[l[k>>>24]]^x[l[k>>>16&255]]^q[l[k>>>
8&255]]^n[l[k&255]]},encryptBlock:function(a,b){this._doCryptBlock(a,b,this._keySchedule,t,r,w,v,l)},decryptBlock:function(a,c){var d=a[c+1];a[c+1]=a[c+3];a[c+3]=d;this._doCryptBlock(a,c,this._invKeySchedule,b,x,q,n,s);d=a[c+1];a[c+1]=a[c+3];a[c+3]=d},_doCryptBlock:function(a,b,c,d,e,j,l,f){for(var m=this._nRounds,g=a[b]^c[0],h=a[b+1]^c[1],k=a[b+2]^c[2],n=a[b+3]^c[3],p=4,r=1;r<m;r++)var q=d[g>>>24]^e[h>>>16&255]^j[k>>>8&255]^l[n&255]^c[p++],s=d[h>>>24]^e[k>>>16&255]^j[n>>>8&255]^l[g&255]^c[p++],t=
d[k>>>24]^e[n>>>16&255]^j[g>>>8&255]^l[h&255]^c[p++],n=d[n>>>24]^e[g>>>16&255]^j[h>>>8&255]^l[k&255]^c[p++],g=q,h=s,k=t;q=(f[g>>>24]<<24|f[h>>>16&255]<<16|f[k>>>8&255]<<8|f[n&255])^c[p++];s=(f[h>>>24]<<24|f[k>>>16&255]<<16|f[n>>>8&255]<<8|f[g&255])^c[p++];t=(f[k>>>24]<<24|f[n>>>16&255]<<16|f[g>>>8&255]<<8|f[h&255])^c[p++];n=(f[n>>>24]<<24|f[g>>>16&255]<<16|f[h>>>8&255]<<8|f[k&255])^c[p++];a[b]=q;a[b+1]=s;a[b+2]=t;a[b+3]=n},keySize:8});u.AES=p._createHelper(d)})();
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

var CryptoJS=CryptoJS||function(e,m){var p={},j=p.lib={},l=function(){},f=j.Base={extend:function(a){l.prototype=this;var c=new l;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
n=j.WordArray=f.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=m?c:4*a.length},toString:function(a){return(a||h).stringify(this)},concat:function(a){var c=this.words,q=a.words,d=this.sigBytes;a=a.sigBytes;this.clamp();if(d%4)for(var b=0;b<a;b++)c[d+b>>>2]|=(q[b>>>2]>>>24-8*(b%4)&255)<<24-8*((d+b)%4);else if(65535<q.length)for(b=0;b<a;b+=4)c[d+b>>>2]=q[b>>>2];else c.push.apply(c,q);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=e.ceil(c/4)},clone:function(){var a=f.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],b=0;b<a;b+=4)c.push(4294967296*e.random()|0);return new n.init(c,a)}}),b=p.enc={},h=b.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],d=0;d<a;d++){var f=c[d>>>2]>>>24-8*(d%4)&255;b.push((f>>>4).toString(16));b.push((f&15).toString(16))}return b.join("")},parse:function(a){for(var c=a.length,b=[],d=0;d<c;d+=2)b[d>>>3]|=parseInt(a.substr(d,
2),16)<<24-4*(d%8);return new n.init(b,c/2)}},g=b.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],d=0;d<a;d++)b.push(String.fromCharCode(c[d>>>2]>>>24-8*(d%4)&255));return b.join("")},parse:function(a){for(var c=a.length,b=[],d=0;d<c;d++)b[d>>>2]|=(a.charCodeAt(d)&255)<<24-8*(d%4);return new n.init(b,c)}},r=b.Utf8={stringify:function(a){try{return decodeURIComponent(escape(g.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return g.parse(unescape(encodeURIComponent(a)))}},
k=j.BufferedBlockAlgorithm=f.extend({reset:function(){this._data=new n.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=r.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,b=c.words,d=c.sigBytes,f=this.blockSize,h=d/(4*f),h=a?e.ceil(h):e.max((h|0)-this._minBufferSize,0);a=h*f;d=e.min(4*a,d);if(a){for(var g=0;g<a;g+=f)this._doProcessBlock(b,g);g=b.splice(0,a);c.sigBytes-=d}return new n.init(g,d)},clone:function(){var a=f.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});j.Hasher=k.extend({cfg:f.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){k.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,b){return(new a.init(b)).finalize(c)}},_createHmacHelper:function(a){return function(b,f){return(new s.HMAC.init(a,
f)).finalize(b)}}});var s=p.algo={};return p}(Math);
(function(){var e=CryptoJS,m=e.lib,p=m.WordArray,j=m.Hasher,l=[],m=e.algo.SHA1=j.extend({_doReset:function(){this._hash=new p.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(f,n){for(var b=this._hash.words,h=b[0],g=b[1],e=b[2],k=b[3],j=b[4],a=0;80>a;a++){if(16>a)l[a]=f[n+a]|0;else{var c=l[a-3]^l[a-8]^l[a-14]^l[a-16];l[a]=c<<1|c>>>31}c=(h<<5|h>>>27)+j+l[a];c=20>a?c+((g&e|~g&k)+1518500249):40>a?c+((g^e^k)+1859775393):60>a?c+((g&e|g&k|e&k)-1894007588):c+((g^e^
k)-899497514);j=k;k=e;e=g<<30|g>>>2;g=h;h=c}b[0]=b[0]+h|0;b[1]=b[1]+g|0;b[2]=b[2]+e|0;b[3]=b[3]+k|0;b[4]=b[4]+j|0},_doFinalize:function(){var f=this._data,e=f.words,b=8*this._nDataBytes,h=8*f.sigBytes;e[h>>>5]|=128<<24-h%32;e[(h+64>>>9<<4)+14]=Math.floor(b/4294967296);e[(h+64>>>9<<4)+15]=b;f.sigBytes=4*e.length;this._process();return this._hash},clone:function(){var e=j.clone.call(this);e._hash=this._hash.clone();return e}});e.SHA1=j._createHelper(m);e.HmacSHA1=j._createHmacHelper(m)})();
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

var CryptoJS=CryptoJS||function(h,s){var f={},t=f.lib={},g=function(){},j=t.Base={extend:function(a){g.prototype=this;var c=new g;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
q=t.WordArray=j.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||u).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=j.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new q.init(c,a)}}),v=f.enc={},u=v.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,
2),16)<<24-4*(b%8);return new q.init(d,c/2)}},k=v.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new q.init(d,c)}},l=v.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},
x=t.BufferedBlockAlgorithm=j.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var m=0;m<a;m+=e)this._doProcessBlock(d,m);m=d.splice(0,a);c.sigBytes-=b}return new q.init(m,b)},clone:function(){var a=j.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});t.Hasher=x.extend({cfg:j.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){x.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new w.HMAC.init(a,
d)).finalize(c)}}});var w=f.algo={};return f}(Math);
(function(h){for(var s=CryptoJS,f=s.lib,t=f.WordArray,g=f.Hasher,f=s.algo,j=[],q=[],v=function(a){return 4294967296*(a-(a|0))|0},u=2,k=0;64>k;){var l;a:{l=u;for(var x=h.sqrt(l),w=2;w<=x;w++)if(!(l%w)){l=!1;break a}l=!0}l&&(8>k&&(j[k]=v(h.pow(u,0.5))),q[k]=v(h.pow(u,1/3)),k++);u++}var a=[],f=f.SHA256=g.extend({_doReset:function(){this._hash=new t.init(j.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],m=b[2],h=b[3],p=b[4],j=b[5],k=b[6],l=b[7],n=0;64>n;n++){if(16>n)a[n]=
c[d+n]|0;else{var r=a[n-15],g=a[n-2];a[n]=((r<<25|r>>>7)^(r<<14|r>>>18)^r>>>3)+a[n-7]+((g<<15|g>>>17)^(g<<13|g>>>19)^g>>>10)+a[n-16]}r=l+((p<<26|p>>>6)^(p<<21|p>>>11)^(p<<7|p>>>25))+(p&j^~p&k)+q[n]+a[n];g=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&m^f&m);l=k;k=j;j=p;p=h+r|0;h=m;m=f;f=e;e=r+g|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+m|0;b[3]=b[3]+h|0;b[4]=b[4]+p|0;b[5]=b[5]+j|0;b[6]=b[6]+k|0;b[7]=b[7]+l|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=g.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=g._createHelper(f);s.HmacSHA256=g._createHmacHelper(f)})(Math);
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

var CryptoJS=CryptoJS||function(g,j){var e={},d=e.lib={},m=function(){},n=d.Base={extend:function(a){m.prototype=this;var c=new m;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
q=d.WordArray=n.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=j?c:4*a.length},toString:function(a){return(a||l).stringify(this)},concat:function(a){var c=this.words,p=a.words,f=this.sigBytes;a=a.sigBytes;this.clamp();if(f%4)for(var b=0;b<a;b++)c[f+b>>>2]|=(p[b>>>2]>>>24-8*(b%4)&255)<<24-8*((f+b)%4);else if(65535<p.length)for(b=0;b<a;b+=4)c[f+b>>>2]=p[b>>>2];else c.push.apply(c,p);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=g.ceil(c/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],b=0;b<a;b+=4)c.push(4294967296*g.random()|0);return new q.init(c,a)}}),b=e.enc={},l=b.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++){var d=c[f>>>2]>>>24-8*(f%4)&255;b.push((d>>>4).toString(16));b.push((d&15).toString(16))}return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f+=2)b[f>>>3]|=parseInt(a.substr(f,
2),16)<<24-4*(f%8);return new q.init(b,c/2)}},k=b.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++)b.push(String.fromCharCode(c[f>>>2]>>>24-8*(f%4)&255));return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f++)b[f>>>2]|=(a.charCodeAt(f)&255)<<24-8*(f%4);return new q.init(b,c)}},h=b.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(b){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},
u=d.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=h.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var b=this._data,d=b.words,f=b.sigBytes,l=this.blockSize,e=f/(4*l),e=a?g.ceil(e):g.max((e|0)-this._minBufferSize,0);a=e*l;f=g.min(4*a,f);if(a){for(var h=0;h<a;h+=l)this._doProcessBlock(d,h);h=d.splice(0,a);b.sigBytes-=f}return new q.init(h,f)},clone:function(){var a=n.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});d.Hasher=u.extend({cfg:n.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,d){return(new a.init(d)).finalize(b)}},_createHmacHelper:function(a){return function(b,d){return(new w.HMAC.init(a,
d)).finalize(b)}}});var w=e.algo={};return e}(Math);
(function(){var g=CryptoJS,j=g.lib,e=j.WordArray,d=j.Hasher,m=[],j=g.algo.SHA1=d.extend({_doReset:function(){this._hash=new e.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(d,e){for(var b=this._hash.words,l=b[0],k=b[1],h=b[2],g=b[3],j=b[4],a=0;80>a;a++){if(16>a)m[a]=d[e+a]|0;else{var c=m[a-3]^m[a-8]^m[a-14]^m[a-16];m[a]=c<<1|c>>>31}c=(l<<5|l>>>27)+j+m[a];c=20>a?c+((k&h|~k&g)+1518500249):40>a?c+((k^h^g)+1859775393):60>a?c+((k&h|k&g|h&g)-1894007588):c+((k^h^
g)-899497514);j=g;g=h;h=k<<30|k>>>2;k=l;l=c}b[0]=b[0]+l|0;b[1]=b[1]+k|0;b[2]=b[2]+h|0;b[3]=b[3]+g|0;b[4]=b[4]+j|0},_doFinalize:function(){var d=this._data,e=d.words,b=8*this._nDataBytes,l=8*d.sigBytes;e[l>>>5]|=128<<24-l%32;e[(l+64>>>9<<4)+14]=Math.floor(b/4294967296);e[(l+64>>>9<<4)+15]=b;d.sigBytes=4*e.length;this._process();return this._hash},clone:function(){var e=d.clone.call(this);e._hash=this._hash.clone();return e}});g.SHA1=d._createHelper(j);g.HmacSHA1=d._createHmacHelper(j)})();
(function(){var g=CryptoJS,j=g.enc.Utf8;g.algo.HMAC=g.lib.Base.extend({init:function(e,d){e=this._hasher=new e.init;"string"==typeof d&&(d=j.parse(d));var g=e.blockSize,n=4*g;d.sigBytes>n&&(d=e.finalize(d));d.clamp();for(var q=this._oKey=d.clone(),b=this._iKey=d.clone(),l=q.words,k=b.words,h=0;h<g;h++)l[h]^=1549556828,k[h]^=909522486;q.sigBytes=b.sigBytes=n;this.reset()},reset:function(){var e=this._hasher;e.reset();e.update(this._iKey)},update:function(e){this._hasher.update(e);return this},finalize:function(e){var d=
this._hasher;e=d.finalize(e);d.reset();return d.finalize(this._oKey.clone().concat(e))}})})();
(function(){var g=CryptoJS,j=g.lib,e=j.Base,d=j.WordArray,j=g.algo,m=j.HMAC,n=j.PBKDF2=e.extend({cfg:e.extend({keySize:4,hasher:j.SHA1,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(e,b){for(var g=this.cfg,k=m.create(g.hasher,e),h=d.create(),j=d.create([1]),n=h.words,a=j.words,c=g.keySize,g=g.iterations;n.length<c;){var p=k.update(b).finalize(j);k.reset();for(var f=p.words,v=f.length,s=p,t=1;t<g;t++){s=k.finalize(s);k.reset();for(var x=s.words,r=0;r<v;r++)f[r]^=x[r]}h.concat(p);
a[0]++}h.sigBytes=4*c;return h}});g.PBKDF2=function(d,b,e){return n.create(e).compute(d,b)}})();























epdRoot = { };
if (typeof(window) !== "undefined") {
  window.EPD = epdRoot;
}
;

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

(function ($, $$) {
  "use strict";

  $$.current = function () {
    return new Date().getTime();
  };

}(epdRoot,
  epdRoot.Time = epdRoot.Time || { }));
/*global CryptoJS:false, RSAKey:false */


(function ($, $$, $$$) {
  "use strict";

  var _defaultKeyBits = 1024
    , _defaultPublicExponent = "00000003"

    , _joinArrays = function (arrays) {
        var result = [ ];
        $.Iterator.each(arrays, function (index, array) {
          result.push(array.length);
          result = result.concat(array);
        });
        return result;
      }

    , _splitArrays = function (array) {
        var results = [ ];
        for (var index = 0; index < array.length; ) {
          var length = array[index];
          index++;
          results.push(array.slice(index, index + length));
          index += length;
        }
        return results;
      }

    , _hexToBase64 = function (hex) {
        return _arrayToBase64(_hexToArray(hex));
      }
    , _base64ToHex = function (base64) {
        return _arrayToHex(_base64ToArray(base64));
      }
    , _arrayToBase64 = function (array) {
        return CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(array));
      }
    , _base64ToArray = function (base64) {
        return CryptoJS.enc.Base64.parse(base64).words;
      }
    , _hexToArray = function (hex) {
        return CryptoJS.enc.Hex.parse(hex).words;
      }
    , _arrayToHex = function (array) {
        return CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.create(array));
      };

  $$$.generateKeyPair = function (keyBits) {
    var rsa = new $$$.RSA.Key()
      , bits = keyBits || _defaultKeyBits
      , modulus, publicExponent, privateExponent;

    rsa.generate(bits, _defaultPublicExponent);

    modulus = _hexToArray(rsa.n.toString(16));
    publicExponent = _hexToArray(_defaultPublicExponent);
    privateExponent = _hexToArray(rsa.d.toString(16));

    return {
      publicKey: { type: "rsaKey", modulus: modulus, exponent: publicExponent },
      privateKey: { type: "rsaKey", modulus: modulus, exponent: privateExponent }
    };
  };

  $$$.encrypt = function (message, publicKey) {
    $$.Coder.ensureType("rsaKey", publicKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPublic(_arrayToHex(publicKey.modulus), _arrayToHex(publicKey.exponent));
    return { type: "rsaEncryptedData", data: $$$.RSA.encrypt(message, rsaKey) };
  };

  $$$.decrypt = function (encrypted, publicKey, privateKey) {
    $$.Coder.ensureType("rsaEncryptedData", encrypted);
    $$.Coder.ensureType("rsaKey", publicKey);
    $$.Coder.ensureType("rsaKey", privateKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPrivate(_arrayToHex(privateKey.modulus), _arrayToHex(publicKey.exponent), _arrayToHex(privateKey.exponent));
    return $$$.RSA.decrypt(encrypted.data, rsaKey);
  };

  $$$.encryptSymmetric = function (message, publicKey) {
    $$.Coder.ensureType("rsaKey", publicKey);

    var key = $$.Symmetric.generateKey()
      , encryptedKey = $$$.encrypt($$.Coder.encode(key), publicKey)
      , encryptedMessage = $$.Symmetric.encrypt(message, key);

    return { type: "rsaAesEncryptedData", key: encryptedKey, data: encryptedMessage };
  };

  $$$.decryptSymmetric = function (encrypted, publicKey, privateKey) {
    $$.Coder.ensureType("rsaAesEncryptedData", encrypted);
    $$.Coder.ensureType("rsaKey", publicKey);
    $$.Coder.ensureType("rsaKey", privateKey);

    var decryptedKey = $$.Coder.decode($$$.decrypt(encrypted.key, publicKey, privateKey));

    return $$.Symmetric.decrypt(encrypted.data, decryptedKey);
  };

  $$$.sign = function (message, publicKey, privateKey) {
    $$.Coder.ensureType("rsaKey", publicKey);
    $$.Coder.ensureType("rsaKey", privateKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPrivate(_arrayToHex(privateKey.modulus), _arrayToHex(publicKey.exponent), _arrayToHex(privateKey.exponent));
    return { type: "rsaSignature", data: $$$.RSA.Signer.signWithSHA256(message, rsaKey) };
  };

  $$$.verify = function (message, signature, publicKey) {
    $$.Coder.ensureType("rsaSignature", signature);
    $$.Coder.ensureType("rsaKey", publicKey);

    var rsaKey = new $$$.RSA.Key();

    rsaKey.setPublic(_arrayToHex(publicKey.modulus), _arrayToHex(publicKey.exponent));
    return $$$.RSA.Signer.verify(message, rsaKey, signature.data);
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { });

(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.encrypt = function (object, publicKey) {
    return $$$.encryptSymmetric(JSON.stringify(object), publicKey);
  };

  $$$$.decrypt = function (encrypted, publicKey, privateKey) {
    return JSON.parse($$$.decryptSymmetric(encrypted, publicKey, privateKey));
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Asymmetric = epdRoot.Crypt.Asymmetric || { },
  epdRoot.Crypt.Asymmetric.Object = epdRoot.Crypt.Asymmetric.Object || { }));

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
        sha256: function (s) {
          return CryptoJS.enc.Hex.stringify(CryptoJS.SHA256(s));
        }
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
/*global CryptoJS:false */


(function ($, $$, $$$) {
  "use strict";

  $$$.generateId = function (length) {
    return CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(length || 16));
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Object = epdRoot.Crypt.Object || { });
/*global CryptoJS:false */


(function ($, $$, $$$) {
  "use strict";

  var _settings = {
        saltSize: 16,
        keySize: 160/32,
        iterations: 1000
      };

  $$$.hash = function (password, parameters) {
    if (!password) {
      throw(new Error("no password given"));
    }
    parameters = parameters || { };

    var salt = parameters.salt || { type: "salt", data: CryptoJS.lib.WordArray.random(_settings.saltSize).words }
      , keySize = parameters.keySize || _settings.keySize
      , iterations = parameters.iterations || _settings.iterations
      , hash = {
          type: "aesKey",
          data: CryptoJS.PBKDF2(password, CryptoJS.lib.WordArray.create(salt.data), { keySize: keySize, iterations: iterations }).words
        };

    return {
      hash: hash,
      salt: salt,
      keySize: keySize,
      iterations: iterations
    };
  };

  $$$.benchmark = function (iterations) {
    var start = $.Time.current()
      , end;

    $$$.hash("sample", { iterations: iterations });
    end = $.Time.current();

    return end - start;
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Password = epdRoot.Crypt.Password || { }));
/*global CryptoJS:false */


(function ($, $$, $$$) {
  "use strict";

  var _keyLength = 16,
      _toBase64 = function (array) {
        return CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(array));
      };

  $$$.generateKey = function () {
    return {
      type: "aesKey",
      data: CryptoJS.lib.WordArray.random(_keyLength).words
    };
  };

  $$$.encrypt = function (message, key) {
    $.Crypt.Coder.ensureType("aesKey", key);

    return {
      type: "aesEncryptedData",
      data: CryptoJS.format.OpenSSL.stringify(
              CryptoJS.AES.encrypt(message, _toBase64(key.data)))
    };
  };

  $$$.decrypt = function (encrypted, key) {
    $.Crypt.Coder.ensureType("aesEncryptedData", encrypted);
    $.Crypt.Coder.ensureType("aesKey", key);

    return CryptoJS.enc.Utf8.stringify(
             CryptoJS.AES.decrypt(
               CryptoJS.format.OpenSSL.parse(encrypted.data), _toBase64(key.data)));
  };

})(epdRoot,
   epdRoot.Crypt = epdRoot.Crypt || { },
   epdRoot.Crypt.Symmetric = epdRoot.Crypt.Symmetric || { });

(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.encrypt = function (object, key) {
    return $$$.encrypt(JSON.stringify(object), key);
  };

  $$$$.decrypt = function (encrypted, key) {
    return JSON.parse($$$.decrypt(encrypted, key));
  };

}(epdRoot,
  epdRoot.Crypt = epdRoot.Crypt || { },
  epdRoot.Crypt.Symmetric = epdRoot.Crypt.Symmetric || { },
  epdRoot.Crypt.Symmetric.Object = epdRoot.Crypt.Symmetric.Object || { }));

(function ($, $$, $$$) {
  "use strict";

  var _dropPrivateKey = function (foreignProfile) {
        delete(foreignProfile.privateKey);
      }

    , _decodePublicKey = function (foreignProfile) {
        foreignProfile.publicKey = $.Crypt.Coder.decode(foreignProfile.publicKey);
      }

    , _decryptContactKeys = function (foreignProfile, profile) {
        $.Iterator.each(foreignProfile.contacts, function (contactId, container) {
          if (profile && profile.publicKey && container.publicKey === $.Crypt.Coder.encode(profile.publicKey)) {
            container.keys =
              $.Crypt.Asymmetric.Object.decrypt(
                $.Crypt.Coder.decode(container.keys), profile.publicKey, profile.privateKey);
            $.Iterator.each(container.keys, function (id, key) {
              container.keys[id] = $.Crypt.Coder.decode(key);
            });
          } else {
            container.publicKey = $.Crypt.Coder.decode(container.publicKey);
            delete(container.keys);
            delete(container.sections);
          }
        });
      }

    , _decryptSections = function (foreignProfile, profile) {
        if (profile && profile.id) {
          var keys = foreignProfile.contacts[profile.id] ? foreignProfile.contacts[profile.id].keys : undefined;
          $.Iterator.each(foreignProfile.sections, function (id, encryptedSection) {
            if ($.Collection.include($.Sections.openIds, id)) {
              foreignProfile.sections[id] = encryptedSection;
            } else {
              var key = keys ? keys[id] : undefined;
              if (key) {
                foreignProfile.sections[id] = $.Crypt.Symmetric.Object.decrypt($.Crypt.Coder.decode(encryptedSection), key);
              } else {
                delete(foreignProfile.sections[id]);
              }
            }
          });
        }
      };

  $$$.unlock = function (foreignProfile, profile) {
    var result = $.Object.clone(foreignProfile);
    _dropPrivateKey(result);
    _decodePublicKey(result);
    _decryptContactKeys(result, profile);
    _decryptSections(result, profile);
    return result;
  };

})(epdRoot,
   epdRoot.Foreign = epdRoot.Foreign || { },
   epdRoot.Foreign.Locker = epdRoot.Foreign.Locker || { });

(function ($, $$, $$$) {
  "use strict";

  var _forContacts = function (contactIds, profileGetFunction, handler) {
        $.Iterator.each(contactIds, function (index, contactId) {
          var contactProfile = profileGetFunction(contactId);
          if (contactProfile) {
            handler(contactId, contactProfile);
          }
        });
      };

  $$$.ids = function (foreignProfile, sectionId) {
    return $.Modules.ids(foreignProfile, sectionId);
  };

  $$$.contents = function (profile, id, profileGetFunction) {
    var contents = { };

    _forContacts($.Contacts.ids(profile), profileGetFunction, function (contactId, contactProfile) {
      var sectionIds = $.Sections.openIds.concat($.Sections.ids(contactProfile));
      $.Iterator.each(sectionIds, function (index, sectionId) {
        if ($.Modules.exists(contactProfile, sectionId, id)) {
          var module = $.Modules.byId(contactProfile, sectionId, id);
          contents[contactId] = contents[contactId] || { };
          contents[contactId][sectionId] = module.content;
        }
      });
    });

    return contents;
  };

  $$$.contentsForSection = function (profile, sectionId, id, profileGetFunction) {
    var contents = { };

    _forContacts($.Contacts.idsBySectionId(profile, sectionId), profileGetFunction, function (contactId, contactProfile) {
      if ($.Modules.exists(contactProfile, sectionId, id)) {
        var module = $.Modules.byId(contactProfile, sectionId, id);
        contents[contactId] = module.content;
      }
    });

    return contents;
  };

}(epdRoot,
  epdRoot.Foreign = epdRoot.Foreign || { },
  epdRoot.Foreign.Modules = epdRoot.Foreign.Modules || { }));

(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.ids = function (foreignProfile) {
    return $.Sections.Synchronisable.ids(foreignProfile);
  };

  $$$$.exists = function (foreignProfile, id) {
    return $.Sections.Synchronisable.exists(foreignProfile, id);
  };

  $$$$.byId = function (foreignProfile, id) {
    return $.Sections.Synchronisable.byId(foreignProfile, id);
  };

  $$$$.memberIds = function (foreignProfile, id) {
    var hangOut = $$$$.byId(foreignProfile, id);
    return hangOut ? hangOut.members : [ ];
  };

  $$$$.isDelegated = function (foreignProfile, id) {
    return $.Sections.Synchronisable.isDelegated(foreignProfile, id);
  };

  $$$$.offered = function (profile, profileGetFunction) {
    var contactIds = $.Contacts.ids(profile)
      , result = { };

    $.Iterator.each(contactIds, function (_, contactId) {
      var foreignProfile = profileGetFunction(contactId);
      if (foreignProfile) {
        var hangOutIds = $$$$.ids(foreignProfile);
        $.Iterator.each(hangOutIds, function (_, hangOutId) {
          if (!$.Sections.Synchronisable.byId(profile, hangOutId)) {
            var hangOut = $$$$.byId(foreignProfile, hangOutId);
            result[hangOutId] = result[hangOutId] || { title: hangOut.title, contactId: contactId };
          }
        });
      }
    });

    return result;
  };

  $$$$.differences = function (profile, id, profileGetFunction) {
    var memberIds = $.Sections.Synchronisable.memberIds(profile, id)
      , moduleIds = $.Modules.ids(profile, id)
      , notParticipating = { }
      , addMembers = { }, removeMembers = { }
      , addModules = { }, removeModules = { }
      , differences = [ ]

      , pushMember = function (container, keys, memberId) {
          $.Iterator.each(keys, function (_, key) {
            container[key] = container[key] || [ ];
            container[key].push(memberId);
          });
        }

      , pushDifferences = function (container, type) {
          $.Iterator.each(container, function (key, memberIds) {
            differences.push({ type: type, id: key, by: memberIds });
          });
        };

    $.Iterator.each(memberIds, function (_, memberId) {
      var foreignProfile = profileGetFunction(memberId);
      if (memberId !== profile.id && foreignProfile && !$$$$.isDelegated(foreignProfile, id)) {
        if ($$$$.exists(foreignProfile, id)) {
          var foreignMemberIds = $$$$.memberIds(foreignProfile, id)
            , addMemberIds = $.Collection.without(foreignMemberIds, memberIds)
            , removeMemberIds = $.Collection.without(memberIds, foreignMemberIds)

            , foreignModuleIds = $$.Modules.ids(foreignProfile, id)
            , addModuleIds = $.Collection.without(foreignModuleIds, moduleIds)
            , removeModuleIds = $.Collection.without(moduleIds, foreignModuleIds);

          $.Collection.remove(addMemberIds, profile.id);
          $.Collection.remove(removeMemberIds, foreignProfile.id);

          pushMember(addMembers, addMemberIds, memberId);
          pushMember(removeMembers, removeMemberIds, memberId);
          pushMember(addModules, addModuleIds, memberId);
          pushMember(removeModules, removeModuleIds, memberId);
        } else {
          pushMember(notParticipating, [ memberId ], profile.id);
        }
      }
    });

    pushDifferences(notParticipating, "not_participating");
    pushDifferences(addMembers, "add_member");
    pushDifferences(removeMembers, "remove_member");
    pushDifferences(addModules, "add_module");
    pushDifferences(removeModules, "remove_module");

    return differences;
  };

}(epdRoot,
  epdRoot.Foreign = epdRoot.Foreign || { },
  epdRoot.Foreign.Sections = epdRoot.Foreign.Sections || { },
  epdRoot.Foreign.Sections.Synchronisable = epdRoot.Foreign.Sections.Synchronisable || { }));

(function ($, $$, $$$) {
  "use strict";

  $$$.ids = function (profile) {
    return $.Collection.select($$.ids(profile), function (index, id) {
      return $$$.isSynchronisable(profile, id);
    });
  };

  $$$.exists = function (profile, id) {
    return $$.exists(profile, id);
  };

  $$$.byId = function (profile, id) {
    return $$.byId(profile, id);
  };

  $$$.isSynchronisable = function (profile, id) {
    var section = $$$.byId(profile, id);
    return section && !!section.members;
  };

  $$$.add = function (profile, title, id) {
    var sectionId = $$.add(profile, title, id)
      , section = $$.byId(profile, sectionId);

    section.members = [ ];

    return sectionId;
  };

  $$$.remove = function (profile, id) {
    return $$.remove(profile, id);
  };

  $$$.memberIds = function (profile, id) {
    return $.Collection.select($.Contacts.ids(profile), function (_, contactId) {
      return $$$.isMember(profile, contactId, id);
    });
  };

  $$$.addMember = function (profile, contactId, id) {
    if ($$$.isMember(profile, contactId, id)) {
      return profile;
    }

    var section = $$$.byId(profile, id);
    section.members.push(contactId);
    return $$.addMember(profile, contactId, id);
  };

  $$$.removeMember = function (profile, contactId, id) {
    if (!$$$.isMember(profile, contactId, id)) {
      return profile;
    }

    var section = $$$.byId(profile, id);
    $.Collection.remove(section.members, contactId);
    return $$.removeMember(profile, contactId, id);
  };

  $$$.isMember = function (profile, contactId, id) {
    var section = $$$.byId(profile, id);
    return $$.isMember(profile, contactId, id) && $.Collection.include(section.members, contactId);
  };

  // high level

  $$$.addMembers = function (profile, contactIds, id) {
    return $$.addMembers(profile, contactIds, id, $$$);
  };

  $$$.removeMembers = function (profile, contactIds, id) {
    return $$.removeMembers(profile, contactIds, id, $$$);
  };

  $$$.ensureOnlyMembers = function (profile, contactIds, id) {
    return $$.ensureOnlyMembers(profile, contactIds, id, $$$);
  };

  $$$.delegateTo = function (profile, contactId, id) {
    var hangOut = $$$.byId(profile, id);
    hangOut.administrationDelegatedTo = contactId;

    return profile;
  };

  $$$.removeDelegation = function (profile, id) {
    var hangOut = $$$.byId(profile, id);
    delete(hangOut.administrationDelegatedTo);
    return profile;
  };

  $$$.delegatedTo = function (profile, id) {
    var hangOut = $$$.byId(profile, id);
    return hangOut.administrationDelegatedTo;
  };

  $$$.isDelegated = function (profile, id) {
    var hangOut = $$$.byId(profile, id);
    return !!hangOut && !!hangOut.administrationDelegatedTo;
  };

  $$$.followAllDelegations = function (profile, profileGetFunction) {
    var result = { };

    $.Iterator.each($$$.ids(profile), function (_, id) {
      result[ id ] = $$$.followDelegation(profile, id, profileGetFunction);
    });

    return result;
  };

  $$$.followDelegation = function (profile, id, profileGetFunction) {
    var result = { }

      , findDelegationTargetProfile = function () {
          var result = profile;

          while (result && $$$.isDelegated(result, id)) {
            var nextProfileId = $$$.delegatedTo(result, id)
              , nextProfile = profileGetFunction(nextProfileId);

            if (nextProfileId === profile.id) {
              return profile;
            } else {
              if (nextProfile) {
                result = nextProfile;
              } else {
                return result;
              }
            }
          }

          return result;
        }

      , removeDelegation = function () {
          $$$.removeDelegation(profile, id);
        };

    if ($$$.isDelegated(profile, id)) {
      var targetProfile = findDelegationTargetProfile();
      if (targetProfile && targetProfile.id !== profile.id) {
        if (targetProfile.id !== $$$.delegatedTo(profile, id)) {
          $$$.delegateTo(profile, targetProfile.id, id);
        }

        if ($.Collection.include($.Foreign.Sections.Synchronisable.ids(targetProfile), id)) {
          var memberIds = [ profile.id ].concat($$$.memberIds(profile, id))
            , targetMemberIds = [ targetProfile.id ].concat($.Foreign.Sections.Synchronisable.memberIds(targetProfile, id))
            , addMemberIds = $.Collection.without(targetMemberIds, memberIds)
            , removeMemberIds = $.Collection.without(memberIds, targetMemberIds)

            , moduleIds = $.Modules.ids(profile, id)
            , targetModuleIds = $.Foreign.Modules.ids(targetProfile, id)
            , addModuleIds = $.Collection.without(targetModuleIds, moduleIds)
            , removeModuleIds = $.Collection.without(moduleIds, targetModuleIds);

          if (addMemberIds.length > 0) { result.addMembers = addMemberIds; }
          if (removeMemberIds.length > 0) { result.removeMembers = removeMemberIds; }
          if (addModuleIds.length > 0) { result.addModules = addModuleIds; }
          if (removeModuleIds.length > 0) { result.removeModules = removeModuleIds; }
        } else {
          removeDelegation();
        }
      } else {
        removeDelegation();
      }
    }

    return result;
  };

}(epdRoot,
  epdRoot.Sections = epdRoot.Sections || { },
  epdRoot.Sections.Synchronisable = epdRoot.Sections.Synchronisable || { }));

(function ($, $$) {
  "use strict";

  $$.ids = function (profile) {
    var ids = [ ];
    $.Iterator.each(profile.contacts, function (id) {
      if (profile.id !== id) {
        ids.push(id);
      }
    });
    return ids;
  };

  $$.idsBySectionId = function (profile, sectionId) {
    return $.Collection.select($$.ids(profile), function (index, id) {
      return !!profile.contacts[id].keys[sectionId];
    });
  };

  $$.publicKeyForContactId = function (profile, contactId) {
    return profile.contacts[contactId].publicKey;
  };

  $$.keysForContactId = function (profile, contactId) {
    return profile.contacts[contactId].keys;
  };

  $$.keyForContactIdAndSectionId = function (profile, contactId, sectionId) {
    return profile.contacts[contactId].keys[sectionId];
  };

  $$.add = function (profile, id, publicKey) {
    var contacts = profile.contacts;

    if (contacts[id]) {
      return profile;
    }

    contacts[id] = {
      publicKey: publicKey,
      keys: { }
    };

    if (profile.id !== id) {
      contacts[id].sections = [ ];
    }

    return profile;
  };

  $$.remove = function (profile, id) {
    delete(profile.contacts[id]);
    return profile;
  };

  $$.ensureAdded = function (profile, ids, profileGetFunction) {
    var contactIds = $$.ids(profile);

    $.Iterator.each(ids, function (_, id) {
      var contactProfile = profileGetFunction(id);
      if (contactProfile && !$.Collection.include(contactIds, id)) {
        profile = $$.add(profile, contactProfile.id, contactProfile.publicKey);
      }
    });

    return profile;
  };

  $$.ensureRemoved = function (profile, ids) {
    var contactIds = $$.ids(profile);

    $.Iterator.each(ids, function (_, id) {
      if ($.Collection.include(contactIds, id)) {
        profile = $$.remove(profile, id);
      }
    });

    return profile;
  };

}(epdRoot,
  epdRoot.Contacts = epdRoot.Contacts || { }));

(function ($, $$) {
  "use strict";

  $$.generate = function (keyBits) {
    var id = $.Crypt.Object.generateId()
      , keyPair = $.Crypt.Asymmetric.generateKeyPair(keyBits)
      , profile = {
          id: id,
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
          version: 1,
          contacts: { },
          sections: { }
        };

    $.Contacts.add(profile, id, keyPair.publicKey);
    $.Sections.add(profile, undefined, "open");
    $.Sections.add(profile, undefined, "closed");
    $.Modules.add(profile, "open", "build_in:com.anyaku.Basic");

    return profile;
  };

})(epdRoot,
   epdRoot.Generator = epdRoot.Generator || { });

(function ($, $$) {
  "use strict";

  var _encryptSections = function (profile) {
        $.Iterator.each(profile.sections, function (id, section) {
          if ($.Collection.include($.Sections.openIds, id)) {
            profile.sections[id] = section;
          } else {
            var key = $.Sections.findKey(profile.contacts, id);
            profile.sections[id] = $.Crypt.Coder.encode(
                                    $.Crypt.Symmetric.Object.encrypt(section, key));
          }
        });
      }

    , _encryptContactKeys = function (profile, closedSectionKey) {
        $.Iterator.each(profile.contacts, function (contactId, contact) {
          var keys = contact.keys;
          if (keys) {
            $.Iterator.each(keys, function (id, key) {
              keys[id] = $.Crypt.Coder.encode(key);
            });
            contact.keys = $.Crypt.Coder.encode(
                               $.Crypt.Asymmetric.Object.encrypt(keys, contact.publicKey));
          }
          contact.publicKey = $.Crypt.Coder.encode(contact.publicKey);

          // fix for old profiles that still have this obsolete sections key
          if (contactId === profile.id) {
            delete(contact.sections);
          }

          if (contact.sections) {
            contact.sections = $.Crypt.Coder.encode(
                                 $.Crypt.Symmetric.Object.encrypt(contact.sections, closedSectionKey));
          }
        });
      }

    , _encryptPrivateKey = function (profile, password) {
        var encodedPrivateKey = $.Crypt.Coder.encode(profile.privateKey)
          , encryptedPrivateKey = $.Crypt.Symmetric.encrypt(encodedPrivateKey, password.hash)
          , encodedEncryptedPrivateKey = $.Crypt.Coder.encode(encryptedPrivateKey)
          , encodedSalt = $.Crypt.Coder.encode(password.salt);

        profile.privateKey = {
          encrypted: encodedEncryptedPrivateKey,
          salt: encodedSalt,
          keySize: password.keySize,
          iterations: password.iterations
        };
      }

    , _encodePublicKey = function (profile) {
        profile.publicKey = $.Crypt.Coder.encode(profile.publicKey);
      }

    , _sign = function (profile, publicKey, privateKey) {
        profile.signature = $.Crypt.Coder.encode($.Signer.sign(profile, publicKey, privateKey));
      }

    , _verify = function (profile, publicKey) {
        if (!profile.signature) {
          throw(new Error("missing profile signature"));
        }
        var signature = $.Crypt.Coder.decode(profile.signature);
        if (!$.Signer.verify(profile, signature, publicKey)) {
          throw(new Error("invalid profile signature"));
        }
      }

    , _decodePublicKey = function (profile) {
        profile.publicKey = $.Crypt.Coder.decode(profile.publicKey);
      }

    , _decryptPrivateKey = function (profile, password) {
        try {
          var decodedEncryptedPrivateKey = $.Crypt.Coder.decode(profile.privateKey.encrypted)
            , decryptedPrivateKey = $.Crypt.Symmetric.decrypt(decodedEncryptedPrivateKey, password.hash);

          profile.privateKey = $.Crypt.Coder.decode(decryptedPrivateKey);
        } catch (error) {
          throw(/^Malformed/.exec(error.message) || /^Type.+not supported!$/.exec(error.message) ?
            new Error("invalid password") : error);
        }
      }

    , _decryptOwnContactKeys = function (profile) {
        var contact = profile.contacts[profile.id];
        contact.publicKey = $.Crypt.Coder.decode(contact.publicKey);
        contact.keys = $.Crypt.Asymmetric.Object.decrypt(
                         $.Crypt.Coder.decode(contact.keys), profile.publicKey, profile.privateKey);
        $.Iterator.each(contact.keys, function (id, key) {
          contact.keys[id] = $.Crypt.Coder.decode(key);
        });
      }

    , _decryptContactKeys = function (profile, closedSectionKey) {
        $.Iterator.each(profile.contacts, function (id, contact) {
          if (id !== profile.id) {
            if (contact.sections) {
              contact.sections = $.Crypt.Symmetric.Object.decrypt(
                                   $.Crypt.Coder.decode(contact.sections), closedSectionKey);
            }
            contact.publicKey = $.Crypt.Coder.decode(contact.publicKey);
            contact.keys = { };
            $.Iterator.each(contact.sections, function (index, sectionId) {
              contact.keys[sectionId] = $.Sections.findKey(profile.contacts, sectionId);
            });
          }
        });
      }

    , _decryptSections = function (profile) {
        var keys = profile.contacts[profile.id] ? profile.contacts[profile.id].keys : undefined;
        if (!keys) { return; }
        $.Iterator.each(profile.sections, function (id, encryptedSection) {
          if ($.Collection.include($.Sections.openIds, id)) {
            profile.sections[id] = encryptedSection;
          } else {
            var key = keys[id];
            profile.sections[id] = key ?
              $.Crypt.Symmetric.Object.decrypt($.Crypt.Coder.decode(encryptedSection), key) :
              undefined;
          }
        });
      };

  $$.lock = function (unlockedProfile, password) {
    var profile = $.Object.clone(unlockedProfile);
    _encryptSections(profile);
    _encryptContactKeys(profile, $.Sections.findKey(unlockedProfile.contacts, "closed"));
    _encryptPrivateKey(profile, password);
    _encodePublicKey(profile);
    _sign(profile, unlockedProfile.publicKey, unlockedProfile.privateKey);
    return profile;
  };

  $$.unlock = function (lockedProfile, password) {
    var profile = $.Object.clone(lockedProfile);
    _verify(profile, $.Crypt.Coder.decode(lockedProfile.publicKey));
    _decodePublicKey(profile);
    _decryptPrivateKey(profile, password);
    _decryptOwnContactKeys(profile);
    _decryptContactKeys(profile, $.Sections.findKey(profile.contacts, "closed"));
    _decryptSections(profile);
    return profile;
  };

})(epdRoot,
   epdRoot.Locker = epdRoot.Locker || { });

(function ($, $$) {
  "use strict";

  $$.ids = function (profile, sectionId) {
    var section = $.Sections.byId(profile, sectionId);
    return section ? $.Object.keys(section.modules) : [ ];
  };

  $$.exists = function (profile, sectionId, id) {
    var section = $.Sections.byId(profile, sectionId);
    return section && !$.Crypt.Coder.isEncoded(section) ? !!section.modules[id] : false;
  };

  $$.byId = function (profile, sectionId, id) {
    if (!$$.exists(profile, sectionId, id)) {
      throw(new Error("the module " + id + " does not exists"));
    }
    return $.Sections.byId(profile, sectionId).modules[id];
  };

  $$.ensureOnly = function (profile, sectionId, ids) {
    // remove modules, that are not on the list
    $.Iterator.each($$.ids(profile, sectionId), function (index, id) {
      if (!$.Collection.include(ids, id)) {
        profile = $$.remove(profile, sectionId, id);
      }
    });

    // add modules, that are not added yet
    $.Iterator.each(ids, function (index, id) {
      if (!$$.exists(profile, sectionId, id)) {
        $$.add(profile, sectionId, id);
      }
    });

    return profile;
  };

  $$.ensureAdded = function (profile, sectionId, ids) {
    var moduleIds = $$.ids(profile, sectionId);
    $.Iterator.each(ids, function (_, id) {
      if (!$.Collection.include(moduleIds, id)) {
        profile = $$.add(profile, sectionId, id);
      }
    });
    return profile;
  };

  $$.ensureRemoved = function (profile, sectionId, ids) {
    var moduleIds = $$.ids(profile, sectionId);
    $.Iterator.each(ids, function (_, id) {
      if ($.Collection.include(moduleIds, id)) {
        profile = $$.remove(profile, sectionId, id);
      }
    });
    return profile;
  };

  $$.add = function (profile, sectionId, id) {
    var section = $.Sections.byId(profile, sectionId);

    if ($$.exists(profile, sectionId, id)) {
      throw(new Error("the module " + id + " is already existing"));
    }

    section.modules[id] = {
      content: { }
    };

    return id;
  };

  $$.remove = function (profile, sectionId, id) {
    var section = $.Sections.byId(profile, sectionId);

    delete(section.modules[id]);

    return profile;
  };

  $$.contents = function (profile, id) {
    var contents = { };

    $.Iterator.each($.Sections.fixedIds.concat($.Sections.ids(profile)), function (_, sectionId) {
      if ($$.exists(profile, sectionId, id)) {
        var module = $$.byId(profile, sectionId, id);
        contents[sectionId] = module.content;
      }
    });

    return contents;
  };

}(epdRoot,
  epdRoot.Modules = epdRoot.Modules || { }));

(function ($, $$) {
  "use strict";

  $$.openIds = [ "open" ];
  $$.closedIds = [ "closed" ];
  $$.fixedIds = [ "open", "closed" ];

  $$.ids = function (profile) {
    var results = [ ];
    $.Iterator.each(profile.sections, function (id) {
      if (!$.Collection.include($$.fixedIds, id)) {
        results.push(id);
      }
    });
    return results;
  };

  $$.exists = function (profile, id) {
    return !!profile.sections[id];
  };

  $$.byId = function (profile, id) {
    return profile.sections[id];
  };

  $$.add = function (profile, title, id) {
    id = id || $.Crypt.Object.generateId(4);

    if ($$.exists(profile, id)) {
      throw(new Error("the section " + id + " is already existing"));
    }

    profile.sections[id] = { modules: { } };
    if (title) {
      profile.sections[id].title = title;
    }

    $$.addMember(profile, profile.id, id);

    return id;
  };

  $$.remove = function (profile, id) {
    profile = $$.removeAllMembers(profile, id);
    profile = $$.removeMember(profile, profile.id, id);
    delete(profile.sections[id]);
    return profile;
  };

  $$.memberIds = function (profile, id) {
    return $.Collection.select($.Contacts.ids(profile), function (_, contactId) {
      return $$.isMember(profile, contactId, id);
    });
  };

  $$.addMember = function (profile, contactId, id) {
    if ($$.isMember(profile, contactId, id)) {
      return profile;
    }

    var container = profile.contacts[contactId];
    if (profile.id !== contactId) {
      container.sections.push(id);
    }
    container.keys[id] = $$.findKey(profile.contacts, id) || $.Crypt.Symmetric.generateKey();

    return profile;
  };

  $$.removeMember = function (profile, contactId, id) {
    if (!$$.isMember(profile, contactId, id)) {
      return profile;
    }

    var container = profile.contacts[contactId];
    $.Collection.remove(container.sections, id);
    delete(container.keys[id]);

    return profile;
  };

  $$.isMember = function (profile, contactId, id) {
    return ($.Collection.include($$.openIds, id)) ||
           (!!profile.contacts[contactId] &&
             !!profile.contacts[contactId].keys &&
             !!profile.contacts[contactId].keys[id]);
  };

  $$.findKey = function (contacts, id) {
    var result = $.Collection.detect(contacts, function (_, container) {
      return !!container.keys && !!container.keys[id];
    });
    return result ? result.keys[id] : undefined;
  };

  // high level

  $$.addMembers = function (profile, contactIds, id, base) {
    base = base || $$;
    $.Iterator.each(contactIds, function (_, contactId) {
      base.addMember(profile, contactId, id);
    });
    return profile;
  };

  $$.removeAllMembers = function (profile, id, base) {
    return $$.removeMembers(profile, $$.memberIds(profile, id), id, base);
  };

  $$.removeMembers = function (profile, contactIds, id, base) {
    base = base || $$;
    $.Iterator.each(contactIds, function (_, contactId) {
      base.removeMember(profile, contactId, id);
    });
    return profile;
  };

  $$.ensureOnlyMembers = function (profile, contactIds, id, base) {
    base = base || $$;

    // remove member ids, that are not on the list
    base.removeMembers(profile, $.Collection.without(base.memberIds(profile, id), contactIds), id, base);

    // add member ids, that are not allowed yet
    base.addMembers(profile, contactIds, id, base);

    return profile;
  };

}(epdRoot,
  epdRoot.Sections = epdRoot.Sections || { }));

(function ($, $$) {
  "use strict";

  var _profileWithoutSignature = function (profile) {
        var result = $.Object.clone(profile);
        delete(result.signature);
        return result;
      };

  $$.sign = function (profile, publicKey, privateKey) {
    return $.Crypt.Asymmetric.sign($.Object.stringify(_profileWithoutSignature(profile)), publicKey, privateKey);
  };

  $$.verify = function (profile, signature, publicKey) {
    return $.Crypt.Asymmetric.verify($.Object.stringify(_profileWithoutSignature(profile)), signature, publicKey);
  };

}(epdRoot,
  epdRoot.Signer = epdRoot.Signer || { }));
