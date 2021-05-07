const async = require('async');
const config = require('./config/config');
const request = require('request');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let requestOptions = {};

const BASE_URL = 'https://api.recordedfuture.com';

let domainBlockList = [];
let previousDomainBlockListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

function handleRequestError(request) {
  return (options, expectedStatusCode, callback) => {
    return request(options, (err, resp, body) => {
      if (err || resp.statusCode !== expectedStatusCode) {
        callback({ error: err, statusCode: resp ? resp.statusCode : 'unknown' });
      } else {
        callback(null, body);
      }
    });
  };
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.blocklist !== previousDomainBlockListAsString && options.blocklist.length === 0) {
    Logger.debug('Removing Domain Blocklist Filtering');
    previousDomainBlockListAsString = '';
    domainBlockList = null;
  } else {
    if (options.blocklist !== previousDomainBlockListAsString) {
      previousDomainBlockListAsString = options.blocklist;
      Logger.debug({ domainBlocklist: previousDomainBlockListAsString }, 'Modifying Domain Blocklist Regex');
      domainBlockList = options.blocklist.split(',').map((item) => item.trim());
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function _isEntityBlocklisted(entityObj, options) {
  if (domainBlockList.indexOf(entityObj.value) >= 0) {
    return true;
  }

  if (entityObj.isIPv4 && !entityObj.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entityObj.value)) {
        Logger.debug({ ip: entityObj.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entityObj.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entityObj.value)) {
        Logger.debug({ domain: entityObj.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

function doLookup(entities, options, callback) {
  // this is only used for testing purposes
  let host = BASE_URL;
  if (options.host) {
    host = options.host;
  }

  _setupRegexBlocklists(options);

  let results = [];

  async.forEach(
    entities,
    (entity, done) => {
      if (_isEntityBlocklisted(entity)) {
        results.push({
          entity: entity,
          data: null
        });
        done();
        return;
      }

      let requestOptions = {
        qs: {
          fields: ['risk', 'intelCard', 'sightings'].join(',')
        },
        headers: {
          'X-RFToken': options.apiKey,
          'X-RF-User-Agent': 'polarity'
        }
      };

      if (entity.isIP) {
        requestOptions.url = host + '/v2/ip/' + entity.value;
        requestOptions.qs.fields = requestOptions.qs.fields.split(',').concat('location').join(',');
      } else if (entity.isHash) {
        requestOptions.url = host + '/v2/hash/' + entity.value;
      } else if (entity.isDomain) {
        requestOptions.url = host + '/v2/domain/' + entity.value;
      } else if (entity.isURL) {
        requestOptions.url = host + '/v2/url/' + encodeURIComponent(entity.value);
      } else if (entity.type === 'cve') {
        requestOptions.url = host + '/v2/vulnerability/' + entity.value;
      } else {
        done({ detail: 'Unknown entity type received', err: new Error('unknown entity type') });
        return;
      }

      requestWithDefaults(requestOptions, 200, (err, data) => {
        if ((err && err.statusCode === 404) || (data && data.data.risk.score < options.minimumScore)) {
          results.push({
            entity: entity,
            data: null
          });
          done();
          return;
        }

        if (err && err.statusCode === 403) {
          Logger.error('API Quota exceeded');
          done({ detail: 'API quota exceeded', err: err });
          return;
        }

        if (err && err.statusCode !== 404) {
          Logger.error('error looking up entity', { entity: entity });
          done({
            detail: 'Unexpected Error',
            err
          });
          return;
        }

        let risk = data.data.risk;

        results.push({
          entity: entity,
          data: {
            summary: [risk.criticalityLabel, `Risk Score: ${risk.score}`, `Rules: ${risk.riskString}`],
            details: data.data
          }
        });
        Logger.trace({ results }, 'Results');
        done();
      });
    },
    (err) => {
      if (err) {
        Logger.error('Error during lookup', { err: err });
      }

      callback(err, results);
    }
  );
}

function startup(logger) {
  Logger = logger;

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    requestOptions.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    requestOptions.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    requestOptions.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    requestOptions.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    requestOptions.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestOptions.json = true;

  requestWithDefaults = handleRequestError(request.defaults(requestOptions));
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(errors, options, 'apiKey', 'You must provide an API key.');

  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
