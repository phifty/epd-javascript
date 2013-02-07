
describe("Collection", function () {

  var namespace = epdRoot.Collection;

  describe("#include", function () {

    var array = [ 1, 2, 3, 4, 5 ];

    it("should return true if the given value is in the given array", function () {
      var result = namespace.include(array, 2);
      expect(result).toBeTruthy();
    });

    it("should return false if the given value is not in the given array", function () {
      var result = namespace.include(array, 12);
      expect(result).toBeFalsy();
    });

  });

  describe("#map", function () {

    it("should map each element in the given array with the given function", function () {
      var results = namespace.map([ 1, 2, 3, 4 ], function (index, item) {
        return item + 1;
      });
      expect(results).toEqual([ 2, 3, 4, 5 ]);
    });

  });

  describe("#reduce", function () {

    it("should return the reduced array of items", function () {
      var result = namespace.reduce([ 1, 5, 3, 4 ], 0, function (currentResult, item) {
        return currentResult < item ? item : currentResult;
      });
      expect(result).toEqual(5);
    });

  });

  describe("#detect", function () {

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

  describe("#detectObjectWith", function () {

    var array = [ { test: "value" }, { test: "another value" } ];

    it("should returns the first object where the given key/value pair exists", function () {
      var result = namespace.detectObjectWith(array, "test", "another value");
      expect(result).toEqual({ test: "another value" });
    });

  });

  describe("#select", function () {

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

  describe("#selectObjectsWith", function () {

    var array = [ { test: "value" }, { test: "another value" } ];

    it("should returns the all objects where the given key/value pair exists", function () {
      expect(namespace.selectObjectsWith(array, "test", "another value")).toEqual([ { test: "another value" } ]);
    });

  });

  describe("#selectTruthy", function () {

    var array = [ 1, null, 2, undefined, 3, false, 4 ];

    it("should return only elements of the given array that are truthy", function () {
      var result = namespace.selectTruthy(array);
      expect(result).toEqual([ 1, 2, 3, 4 ]);
    });

  });

  describe("#remove", function () {

    var array = [ "one", "two", "three", "two" ];

    it("should remove all item that equals the given one", function () {
      namespace.remove(array, "two");
      expect(array).toEqual([ "one", "three" ]);
    });

  });

  describe("#removeObjectsWith", function () {

    var array = [ { test: "value" }, { test: "another value" } ];

    it("should remove all objects that contain the given key/value pair", function () {
      namespace.removeObjectsWith(array, "test", "value");
      expect(array).toEqual([ { test: "another value" } ]);
    });

  });

  describe("#removeDuplicates", function () {

    it("should return an array where all duplicates are removed", function () {
      var result = namespace.removeDuplicates([ 1, 2, 3, 1, 4 ]);
      expect(result).toEqual([ 1, 2, 3, 4]);
    });

    it("should identify duplicates with a custom equal-function", function () {
      var result = namespace.removeDuplicates([ { value: 1 }, { value: 1 } ], function (a, b) { return a.value == b.value; });
      expect(result).toEqual([ { value: 1 } ]);
    });

    it("should do nothing if undefined is passed", function () {
      expect(function () {
        namespace.removeDuplicates(undefined);
      }).not.toThrow();
    });

  });

  describe("#compare", function () {

    it("should return true if two equal arrays are given", function () {
      var result = namespace.compare([ 1, 2, 3 ], [ 1, 2, 3 ]);
      expect(result).toBeTruthy();
    });

  });

  describe("#without", function () {

    it("should return an array with all elements of the first given array excluding the elements of the second given array", function () {
      var result = namespace.without([ 1, 2, 3, 4, 5, 6 ], [ 3, 5, 7 ]);
      expect(result).toEqual([ 1, 2, 4, 6 ]);
    });

  });

  describe("#pair", function () {

    it("should apply each pair of element-siblings from the given array to the given handler and the results", function () {
      var result = namespace.pair([ 1, 2, 3, 4, 5, 6, 7, 8 ], function (a, b) {
        return a + b;
      });
      expect(result).toEqual([ 3, 5, 7, 9, 11, 13, 15 ]);
    });

  });

});
