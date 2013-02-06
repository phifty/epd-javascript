
describe("Crypt.Coder", function () {

  var namespace = epdRoot.Crypt.Coder;

  describe("#encode", function () {

    it("should throw an error if the given type is not supported", function () {
      expect(function () {
        namespace.encode({ type: "test" });
      }).toThrow("Type test is not supported!");
    });

    it("should return a encoded version of the given object", function () {
      var encoded = namespace.encode(fixtures.rsaKey());
      expect(encoded).toEqual("AAAAAAwAAAAEAAAACAAAAAwAAAAMAAAAEAAAABQAAAAY=");
    });

  });

  describe("#decode", function () {

    it("should throw an error if the included type is not supported", function () {
      expect(function () {
        namespace.decode("/AAAAAwAAAAEAAAACAAAAAwAAAAMAAAAEAAAABQAAAAY=");
      }).toThrow("Type Nr. 63 is not supported!");
    });

    it("should return the decoded object", function () {
      var decoded = namespace.decode(fixtures.encodedRsaKey());
      expect(decoded).toEqual(fixtures.rsaKey());
    });

  });

  describe("#ensureType", function () {

    it("should throw an error if the given object doesn't have the given type", function () {
      expect(function () {
        namespace.ensureType("test", { type: "something_else" });
      }).toThrow("The value {\"type\":\"something_else\"} need to be of type test!");
    });

    it("should throw an error if undefined is given", function () {
      expect(function () {
        namespace.ensureType("test", undefined);
      }).toThrow("The value undefined need to be of type test!");
    });

  });

  describe("#isEncoded", function () {

    it("should return true is the given value is encoded", function () {
      var result = namespace.isEncoded("AAAAAAwAAAAEAAAACAAAAAwAAAAMAAAAEAAAABQAAAAY=")
      expect(result).toBeTruthy();
    });

  });

});
