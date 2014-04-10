/**
 * @license
 * Node Honeypot 2.3.0 <http://lodash.com/>
 * Copyright 2014 Piotr Rochala <http://rocha.la/>
 * Based on original PHP class by smithweb <http://smith-web.net/>
 * Available under MIT license <http://opensource.org/licenses/mit-license.php>
 */
var dns = require('dns');

module.exports = function(key) {

  var api_key = key;

  var visitor_type = {
    0: 'Search Engine Bot',
    1: 'Suspicious',
    2: 'Harvester',
    3: 'Suspicious, Harvester',
    4: 'Comment Spammer',
    5: 'Suspicious, Comment Spammer',
    6: 'Harvester, Comment Spammer',
    7: 'Suspicious, Harvester, Comment Spammer'
  };

  var search_engine = {
    0: 'Undocumented',
    1: 'AltaVista',
    2: 'Ask',
    3: 'Baidu',
    4: 'Excite',
    5: 'Google',
    6: 'Looksmart',
    7: 'Lycos',
    8: 'MSN',
    9: 'Yahoo',
    10: 'Cuil',
    11: 'InfoSeek',
    12: 'Miscellaneous'
  };

  // Raw Response from http:BL query
  var _response = [];

  /**
   * Performs query of the httpBL service, using a DNS Query.
   *
   * See http://www.projecthoneypot.org/httpbl_api.php for
   * information on proper format and possible responses.
   *
   */
  this.query = function(ip, callback) {

    var reversed_ip = ip.split('.').reverse().join('.')

    dns.resolve4([api_key, reversed_ip, 'dnsbl.httpbl.org'].join('.'), function(err, data) {
      if (data) {
        _response = data.toString().split('.').map(Number);
        callback(null, data);
      } else {
        callback(err, null);
      }
    })
  }

  /**
   * Checks if the ip address was listed in the httpBL
   *
   * @return bool True if listed, False if not listed
   */
  this.isListed = function() {
    if (_response[0] === 127) {
      return true;
    }
    return false;
  }

  /**
   * Returns vistor type as integer
   *
   * @return int|bool Vistor type or false if not in httBL
   */
  this.getVisitorType = function() {
    if (this.isListed()) {
      return _response[3];
    }
    return false;
  }

  /**
   * Returns string containing a text description of the visitor type
   *
   * @return string|bool Visitor type if listed in httpBL, false if not
   */
  this.getFormattedVisitorType = function() {
      if (this.isListed()) {
          if (_response[3] === 0) {
              return visitor_type[_response[3]] + ' (' + search_engine[_response[2]] + ')';
          } else {
              return visitor_type[_response[3]];
          }
      } else {
          return false;
      }
  }

  /**
   * Gets the threat rating for an ip address if it is listed in the httpBL.
   *
   * @return int Threat score (out of a possible 255)
   */
  this.getThreatRating = function() {
    if (this.isListed()) {
      return _response[2];
    }
    return 0;
  }

  /**
   * Gets the number of days since an event was tracked for an ip address
   * if it is listed in the httpBL.
   *
   * @return int Number of days since most recent event (up to max of 255)
   */
  this.getRecency = function() {
    if (this.isListed()) {
      return _response[1];
    }
    return 0;
  }

  /**
   * Checks whether the ip address belongs to a search engine bot or company
   *
   * @return boolean True of ip belongs to search engine, false if not
   */
  this.isSearchEngine = function() {
    if (this.isListed() && _response[3] === 0) {
      return true;
    }
    return false;
  }

  /**
   * @return Array containing response details
   */
  this.getRawResponse = function() {
    return _response;
  }

  /**
   * Sets raw response, useful for testing
   */
  this.setRawResponse = function(value) {
    _response = value;
  }

  /*
   * Returns a formatted message with details about the IP address
   *
   * @param string format type of output for the response, text or html
   * @return string Formatted string of response info
   */
  this.getFormattedResponse = function(format) {

    if (!format) {
        format = 'text';
    }

    var line_end = "\n";
    var output = '';

    if (format == 'html') {
        line_end = "<br />\n";
    }

    if (this.isListed()) {
      output += this.getFormattedVisitorType() + line_end;
      if (!this.isSearchEngine()) {
        output += "Threat Rating: " + this.getThreatRating() + " / 255" + line_end;
        output += "Recency: " + this.getRecency() + " / 255" + line_end;
      }
    }

    return output;
  }
};
