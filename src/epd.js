//= require ./vendor/crypt.js
//= require_self
//= require_tree ./common
//= require_tree ./crypt
//= require_tree ./foreign
//= require_tree ./sections
//= require ./contacts
//= require ./generator
//= require ./locker
//= require ./modules
//= require ./sections
//= require ./signer

epdRoot = { };
if (typeof(window) !== "undefined") {
  window.EPD = epdRoot;
}
