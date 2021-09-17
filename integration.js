const config = require('./config/config');
const request = require('request');
const fs = require('fs');
const _ = require('lodash');
const Bottleneck = require('bottleneck');

let Logger;
let requestWithDefaults;
let limiter;

const BASE_URL = 'https://api.recordedfuture.com';

let domainBlockList = [];
let previousDomainBlockListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

function _setupLimiter(options) {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10), // no more than 5 lookups can be running at single time
    highWater: 50, // no more than 50 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10) // don't run lookups faster than 1 every 200 ms
  });
}

function handleRequestError(request) {
  return (options, expectedStatusCode, callback) => {
    return request(options, (err, resp, body) => {
      if (err || resp.statusCode !== expectedStatusCode) {
        const error = err && JSON.parse(JSON.stringify(err, Object.getOwnPropertyNames(err)));
        const errorResult = {
          error,
          statusCode: resp ? resp.statusCode : 'unknown',
          body
        };
        Logger.error(errorResult, 'Request or Status Code Error');
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
  const lookupResults = [];
  const errors = [];
  const blockedEntities = [];
  let numConnectionResets = 0;
  let numThrottled = 0;
  let hasAnyValidEntities = false;

  if (!limiter) _setupLimiter(options);

  let host = BASE_URL;
  if (options.host) {
    host = options.host;
  }

  _setupRegexBlocklists(options);

  entities.forEach((entity) => {
    if (!_isEntityBlocklisted(entity)) {
      hasAnyValidEntities = true;
      limiter.submit(_lookupEntity, entity, options, host, (err, result) => {
        const maxRequestQueueLimitHit =
          (_.isEmpty(err) && _.isEmpty(result)) || (err && err.message === 'This job has been dropped by Bottleneck');

        const statusCode = _.get(err, 'errors[0].status', '');
        const isGatewayTimeout = statusCode === '502' || statusCode === '504';
        const isConnectionReset = _.get(err, 'errors[0].meta.err.code', '') === 'ECONNRESET';

        if (maxRequestQueueLimitHit || isConnectionReset || isGatewayTimeout) {
          // Tracking for logging purposes
          if (isConnectionReset || isGatewayTimeout) numConnectionResets++;
          if (maxRequestQueueLimitHit) numThrottled++;
          const resultObject = {
            entity,
            isVolatile: true,
            data: {
              summary: ['Search Limit Reached'],
              details: { errorMessage: 'Search failed due to too many requests to Recorded Future at one time.' }
            }
          };

          resultObject.data.details.general = {
            maxRequestQueueLimitHit,
            isConnectionReset,
            isGatewayTimeout
          };

          lookupResults.push(resultObject);
        } else if (err) {
          errors.push(err);
        } else {
          lookupResults.push(result);
        }

        if (lookupResults.length + errors.length === entities.length) {
          if (numConnectionResets > 0 || numThrottled > 0) {
            Logger.warn(
              {
                numEntitiesLookedUp: entities.length,
                numConnectionResets: numConnectionResets,
                numLookupsThrottled: numThrottled
              },
              'Lookup Limit Error'
            );
          }
          // we got all our results
          if (errors.length > 0) {
            callback(errors);
          } else {
            callback(null, lookupResults);
          }
        }
      });
    } else {
      blockedEntities.push({ entity, data: null });
    }
  });

  // This can occur if there are no valid entities to lookup so we need a safe guard to make
  // sure we still call the callback.
  if (!hasAnyValidEntities) {
    callback(null, blockedEntities);
  }
}

const _lookupEntity = (entity, options, host, callback) => {
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
    requestOptions.url = host + '/v2/domain/' + encodeURIComponent(entity.value);
  } else if (entity.isURL) {
    requestOptions.url = host + '/v2/url/' + encodeURIComponent(entity.value);
  } else if (entity.type === 'cve') {
    requestOptions.url = host + '/v2/vulnerability/' + entity.value;
  } else {
    callback({ detail: 'Unknown entity type received', err: new Error('unknown entity type') });
    return;
  }

  requestWithDefaults(requestOptions, 200, (err, data) => {
    const entityNotFound = (err && err.statusCode === 404)
    const entityDoesNotHaveMinScore = (data && data.data && data.data.risk && (data.data.risk.score || data.data.risk.score === 0)
        ? data.data.risk.score
        : options.minimumScore) < options.minimumScore

    if (entityNotFound || entityDoesNotHaveMinScore) return callback(null, { entity, data: null });

    if (err && [403, 401].includes(err.statusCode)) {
      const baseErrorMessage =
        (data.error && (data.error.message || data.error.reason)) ||
        err.message ||
        (err.statusCode === 401 && 'API Key is not working and could be incorrect') ||
        'Unknown Cause';

      const optionalStatusCode =
        err.statusCode || data.status ? `.\n\nStatus Code: ${err.statusCode || data.status}` : '';

      const optionalTraceId = data.traceId ? `\n\nTrace ID: ${data.traceId}` : '';

      return callback(null, {
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
    }

    if (err) {
      Logger.error('error looking up entity', { entity });
      callback({
        detail: 'Unexpected Error',
        err,
        data
      });
      return;
    }

    let risk = data.data.risk;

    callback(null, {
      entity,
      data: {
        summary: [risk.criticalityLabel, `Risk Score: ${risk.score}`, `Rules: ${risk.riskString}`],
        details: data.data
      }
    });
  });
};

function startup(logger) {
  Logger = logger;
  let requestOptions = {};

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

  if (options.minimumScore.value < 0) {
    errors = errors.concat({
      key: 'minimumScore',
      message: 'Minimum Score must be 0 or higher'
    });
  }

  if (options.maxConcurrent.value < 1) {
    errors = errors.concat({
      key: 'maxConcurrent',
      message: 'Max Concurrent Requests must be 1 or higher'
    });
  }
  
  if (options.minTime.value < 1) {
    errors = errors.concat({
      key: 'minTime',
      message: 'Minimum Time Between Lookups must be 1 or higher'
    });
  }

  callback(null, errors);
}

function onMessage(payload, options, callback) {
  switch (payload.action) {
    case 'RETRY_LOOKUP':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
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
