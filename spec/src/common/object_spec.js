
describe("Object", function () {

  var namespace = epdRoot.Object;

  describe("#keys", function () {

    it("should return an array with the keys of the given object", function () {
      var keys = namespace.keys({ test: "value", another: "test value" });
      expect(keys).toEqual([ "test", "another" ]);
    });

  });

  describe("#clone", function () {

    var object = { test: "value", nested: { test: "value" } };

    it("should return a copy of the given object", function () {
      var clonedObject = namespace.clone(object);
      expect(clonedObject).toEqual(object);
      expect(clonedObject).not.toBe(object);
    });

  });

  describe("#valueIn", function () {

    it("should return a the value from a nested object structure specified by the given data path", function () {
      var value = namespace.valueIn({ nested: { test: "value" } }, "nested.test");
      expect(value).toEqual("value");
    });

  });

  describe("#stringify", function () {

    it("should return the string version of the given number", function () {
      var result = namespace.stringify(3);
      expect(result).toEqual("3");
    });

    it("should return the string if one is given", function () {
      var result = namespace.stringify("3");
      expect(result).toEqual("3");
    });

    it("should return an empty string if a function is given", function () {
      var result = namespace.stringify(function () { });
      expect(result).toEqual("");
    });

    it("should one-way encode the given object into a string and returns it", function () {
      var result = namespace.stringify({ test: "value" });
      expect(result).toEqual("testvalue");
    });

    it("should keep always the order of the keys alphabetical", function () {
      var result = namespace.stringify({ test: "value", another: "test" });
      expect(result).toEqual("anothertesttestvalue");
    });

    it("should encode nested structures", function () {
      var result = namespace.stringify({ nested: { test: "value" } });
      expect(result).toEqual("nestedtestvalue");
    });

    it("should encode array", function () {
      var result = namespace.stringify([ { test: "value" }, { another: "test" } ]);
      expect(result).toEqual("0testvalue1anothertest");
    });

    it("should not keep the key if the value is undefined", function () {
      var result = namespace.stringify({ test: "value", another: undefined });
      expect(result).toEqual("testvalue");
    });

    it("should encode float numbers the right way", function () {
      var result = namespace.stringify({ latitude: 52.485271999999995, longitude: 13.4372103 });
      expect(result).toEqual("latitude52.485271999999995longitude13.4372103");

      result = namespace.stringify({ latitude: -52.485271999999995, longitude: -13.4372103 });
      expect(result).toEqual("latitude-52.485271999999995longitude-13.4372103");
    });

  });

});
