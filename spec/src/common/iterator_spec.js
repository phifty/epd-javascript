
describe("Iterator", function () {

  var namespace = epdRoot.Iterator;

  describe("#each", function () {

    it("should iterate over each item in an array", function () {
      var count = 0;
      namespace.each([ 1, 2, 3, 4 ], function (index, item) {
        count++;
      });
      expect(count).toEqual(4);
    });

  });

});
