
describe("Iterator", function () {

  var namespace = epdRoot.Iterator;

  describe("keys", function () {

    it("should return an array with the keys of the given object", function () {
      var keys = namespace.keys({ test: "value", another: "test value" });
      expect(keys).toEqual([ "test", "another" ]);
    });

  });

  describe("each", function () {

    it("should iterate over each item in an array", function () {
      var count = 0;
      namespace.each([ 1, 2, 3, 4 ], function (index, item) {
        count++;
      });
      expect(count).toEqual(4);
    });

  });

  describe("map", function () {

    it("should map each element in the given array with the given function", function () {
      var results = namespace.map([ 1, 2, 3, 4 ], function (index, item) {
        return item + 1;
      });
      expect(results).toEqual([ 2, 3, 4, 5 ]);
    });

  });

  describe("reduce", function () {

    it("should return the reduced array of items", function () {
      var result = namespace.reduce([ 1, 5, 3, 4 ], 0, function (currentResult, item) {
        return currentResult < item ? item : currentResult;
      });
      expect(result).toEqual(5);
    });

  });

  describe("detect", function () {

    var array = [ 1, 5, 3, 4 ],
        handler = { func: function () { } };

    beforeEach(function() {
      spyOn(handler, "func").andCallFake(function (index, item) {
        return item === 5;
      });
    });

    it("should returns the first element where the handler returns true", function () {
      var result = namespace.detect(array, handler.func);
      expect(result).toEqual(5);
    });

    it("should stop iterating if the element has been detected", function () {
      namespace.detect(array, handler.func);
      expect(handler.func.callCount).toEqual(2);
    });

  });

  describe("detectObjectWith", function () {

    var array = [ { test: "value" }, { test: "another value" } ];

    it("should returns the first object where the given key/value pair exists", function () {
      var result = namespace.detectObjectWith(array, "test", "another value");
      expect(result).toEqual({ test: "another value" });
    });

  });

  describe("select", function () {

    var array = [ 1, 5, 3, 4 ];
    var handler = { func: function () { } };

    beforeEach(function() {
      spyOn(handler, "func").andCallFake(function (index, item) {
        return item % 2 === 0;
      });
    });

    it("should returns the first element where the handler returns true", function () {
      expect(namespace.select(array, handler.func)).toEqual([ 4 ]);
    });

  });

  describe("selectObjectsWith", function () {

    var array = [ { test: "value" }, { test: "another value" } ];

    it("should returns the all objects where the given key/value pair exists", function () {
      expect(namespace.selectObjectsWith(array, "test", "another value")).toEqual([ { test: "another value" } ]);
    });

  });

  describe("remove", function () {

    var array = [ "one", "two", "three", "two" ];

    it("should remove all item that equals the given one", function () {
      namespace.remove(array, "two");
      expect(array).toEqual([ "one", "three" ]);
    });

  });

  describe("removeObjectsWith", function () {

    var array = [ { test: "value" }, { test: "another value" } ];

    it("should remove all objects that contain the given key/value pair", function () {
      namespace.removeObjectsWith(array, "test", "value");
      expect(array).toEqual([ { test: "another value" } ]);
    });

  });

  describe("countObjectsWith", function () {

    var array = [ { test: "value" }, { test: "another value" }, { test: "value" } ];

    it("should returns the number of objects where the given key/value pair exists", function () {
      expect(namespace.countObjectsWith(array, "test", "value")).toEqual(2);
    });

  });

});
