
var benchmark = {

  measure: function (handler) {
    var start = epdRoot.Time.current();
    handler();
    return epdRoot.Time.current() - start;
  },

  measureEach: function (values, handler) {
    var durations = [ ];
    epdRoot.Iterator.each(values, function (_, value) {
      durations.push(benchmark.measure(function () {
        handler(value);
      }));
    });
    return durations;
  }

};
