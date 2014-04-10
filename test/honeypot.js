
var should = require('should'),
  honeypot = require('../honeypot');

var pot = new honeypot('api_key');

describe('honeypot', function(){

  it('honeypot object should be initialized', function(){
    should(pot).be.ok;
    should(pot.getRawResponse()).be.ok;
    should(pot.getRawResponse().length).equal(0);
  });

  it('honeypot should parse response for bunch of invalid IPs', function(){

    var ip_response = {
      '194.90.36.155' : { // harvester
        response: [127, 1, 36, 3],
        visitor: 3,
        formattedVisitor: 'Suspicious, Harvester',
        threat: 36,
        recency: 1,
        isSearch: false
      },
      '91.207.7.165'  : { // spam server
        response: [127, 1, 58, 5],
        visitor: 5,
        formattedVisitor: 'Suspicious, Comment Spammer',
        threat: 58,
        recency: 1,
        isSearch: false
      },
      '72.22.73.25'   : { // bad web host
        response: [127, 1, 38, 1],
        visitor: 1,
        formattedVisitor: 'Suspicious',
        threat: 38,
        recency: 1,
        isSearch: false
      },
      '62.210.123.137': { // comment spammer
        response: [127, 1, 45, 5],
        visitor: 5,
        formattedVisitor: 'Suspicious, Comment Spammer',
        threat: 45,
        recency: 1,
        isSearch: false
      },
      '121.78.126.228': { // dictionary attack
        response: [127, 1, 56, 1],
        visitor: 1,
        formattedVisitor: 'Suspicious',
        threat: 56,
        recency: 1,
        isSearch: false
      },
      '123.164.66.39' : { // rule breaker
        response: [127, 1, 47, 5],
        visitor: 5,
        formattedVisitor: 'Suspicious, Comment Spammer',
        threat: 47,
        recency: 1,
        isSearch: false
      },
      '157.56.93.85'  : { // crawler
        response: [127, 0, 8, 0],
        visitor: 0,
        formattedVisitor: 'Search Engine Bot (MSN)',
        threat: 8,
        recency: 0,
        isSearch: true
      }
    }

    // simulate response
    for (var i in ip_response) {
      var value = ip_response[i];
      pot.setRawResponse(value.response);

      should(pot.isListed()).equal(true);
      should(pot.getVisitorType()).equal(value.visitor);
      should(pot.getFormattedVisitorType()).equal(value.formattedVisitor);
      should(pot.getThreatRating()).equal(value.threat);
      should(pot.getRecency()).equal(value.recency);
      should(pot.isSearchEngine()).equal(value.isSearch);
    }

  });

  /**
   * NOTE: Tests below are performing actual dns call
   * - verify that IP is still classified as expected in test
   *   https://www.projecthoneypot.org/ip_194.90.36.155
   *   https://www.projecthoneypot.org/ip_91.207.7.165
   * - ensure api_key is updated
   */

  // it('should do actual DNS call', function(done) {
  //   pot.query('194.90.36.155', function(err, data) {
  //     should(pot.isListed()).equal(true);
  //     should(pot.getFormattedVisitorType()).equal('Suspicious, Harvester');
  //     done();
  //   });
  // });

  it('should do actual DNS call', function(done) {
    pot.query('91.207.7.165', function(err, data) {
      should(pot.isListed()).equal(true);
      should(pot.getFormattedVisitorType()).equal('Suspicious, Comment Spammer');
      console.log(pot.getFormattedResponse());
      done();
    });
  });

})