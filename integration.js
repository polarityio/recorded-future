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
        const error = err && JSON.parse(JSON.stringify(err, Object.getOwnPropertyNames(err)))
        const errorResult = {
          error,
          statusCode: resp ? resp.statusCode : 'unknown',
          body
        };
        Logger.error(errorResult, "Request or Status Code Error");
        callback(errorResult, body);
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
        if (
          (err && err.statusCode === 404) ||
          (data && data.data && data.data.risk && (data.data.risk.score || data.data.risk.score === 0)
            ? data.data.risk.score
            : options.minimumScore) < options.minimumScore
        ) {
          results.push({
            entity: entity,
            data: null
          });
          done();
          return;
        }

        if (err && [403, 401].includes(err.statusCode)) {
          const baseErrorMessage =
            (data.error && (data.error.message || data.error.reason)) ||
            err.message ||
            (err.statusCode === 401 && 'API Key is not working and could be incorrect') ||
            'Unknown Cause';
          
          const optionalStatusCode =
            err.statusCode || data.status ? `.\n\nStatus Code: ${err.statusCode || data.status}` : '';

          const optionalTraceId =  data.traceId ? `\n\nTrace ID: ${data.traceId}` : ''

          results.push({
            entity,
            isVolatile: true,
            data: {
              summary: ['Search Returned Error'],
              details: {
                errorMessage: `${baseErrorMessage}${optionalStatusCode}${optionalTraceId}`,
                allowRetry: err.statusCode !== 401
              }
            }
          });
          done();
          return;
        }

        if (err) {
          Logger.error('error looking up entity', { entity });
          done({
            detail: 'Unexpected Error',
            err,
            data
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

  if(options.minimumScore.value < 0) {errors = errors.concat({
    key: 'minimumScore',
    message: "Minimum Score must be 0 or higher"
  });}
  callback(null, errors);
}

function onMessage(payload, options, cb) {
  switch (payload.action) {
    case 'RETRY_LOOKUP':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          cb(err);
        } else {
          cb(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
  }
}

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions
};
