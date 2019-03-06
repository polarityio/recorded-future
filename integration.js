let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;
let requestWithDefaults;
let requestOptions = {};

let host = 'https://api.recordedfuture.com';

let domainBlackList = [];
let previousDomainBlackListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlacklistRegex = null;
let ipBlacklistRegex = null;

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

function _setupRegexBlacklists(options) {
    if (
        options.domainBlacklistRegex !== previousDomainRegexAsString &&
        options.domainBlacklistRegex.length === 0
    ) {
        Logger.debug('Removing Domain Blacklist Regex Filtering');
        previousDomainRegexAsString = '';
        domainBlacklistRegex = null;
    } else {
        if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
            previousDomainRegexAsString = options.domainBlacklistRegex;
            Logger.debug(
                { domainBlacklistRegex: previousDomainRegexAsString },
                'Modifying Domain Blacklist Regex'
            );
            domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
        }
    }

    if (options.blacklist !== previousDomainBlackListAsString && options.blacklist.length === 0) {
        Logger.debug('Removing Domain Blacklist Filtering');
        previousDomainBlackListAsString = '';
        domainBlackList = null;
    } else {
        if (options.blacklist !== previousDomainBlackListAsString) {
            previousDomainBlackListAsString = options.blacklist;
            Logger.debug(
                { domainBlacklist: previousDomainBlackListAsString },
                'Modifying Domain Blacklist Regex'
            );
            domainBlackList = options.blacklist.split(',').map((item) => item.trim());
        }
    }

    if (
        options.ipBlacklistRegex !== previousIpRegexAsString &&
        options.ipBlacklistRegex.length === 0
    ) {
        Logger.debug('Removing IP Blacklist Regex Filtering');
        previousIpRegexAsString = '';
        ipBlacklistRegex = null;
    } else {
        if (options.ipBlacklistRegex !== previousIpRegexAsString) {
            previousIpRegexAsString = options.ipBlacklistRegex;
            Logger.debug({ ipBlacklistRegex: previousIpRegexAsString }, 'Modifying IP Blacklist Regex');
            ipBlacklistRegex = new RegExp(options.ipBlacklistRegex, 'i');
        }
    }
}

function _isEntityBlacklisted(entityObj, options) {
    if (domainBlackList.indexOf(entityObj.value) >= 0) {
        return true;
    }

    if (entityObj.isIPv4 && !entityObj.isPrivateIP) {
        if (ipBlacklistRegex !== null) {
            if (ipBlacklistRegex.test(entityObj.value)) {
                Logger.debug({ ip: entityObj.value }, 'Blocked BlackListed IP Lookup');
                return true;
            }
        }
    }

    if (entityObj.isDomain) {
        if (domainBlacklistRegex !== null) {
            if (domainBlacklistRegex.test(entityObj.value)) {
                Logger.debug({ domain: entityObj.value }, 'Blocked BlackListed Domain Lookup');
                return true;
            }
        }
    }

    return false;
}

function doLookup(entities, options, callback) {
    Logger.trace('looking entities');

    // this is only used for testing purposes
    if (options.host) {
        host = options.host;
    }

    _setupRegexBlacklists(options);

    let results = [];

    async.forEach(entities, (entity, done) => {
        if (_isEntityBlacklisted(entity)) {
            results.push({
                entity: entity,
                data: null
            });
            done();
            return;
        }

        let requestOptions = {
            qs: {
                fields: [
                    'risk',
                    'intelCard',
                    'sightings'
                ]
                    .join(',')
            },
            headers: {
                'X-RFToken': options.apiKey,
                'X-RF-User-Agent': 'polarity'
            }
        };

        if (entity.isIP) {
            requestOptions.url = host + '/v2/ip/' + entity.value;
            requestOptions.qs.fields = requestOptions.qs.fields
                .split(',')
                .concat('location')
                .join(',');
        } else if (entity.isHash) {
            requestOptions.url = host + '/v2/hash/' + entity.value;
        } else if (entity.isDomain) {
            requestOptions.url = host + '/v2/domain/' + entity.value;
        } else if (entity.isURL) {
            requestOptions.url = host + '/v2/url/' + encodeURIComponent(entity.value);
        } else {
            done({ err: new Error('unknown entity type') });
            return
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
                Logger.error('API Quota exceeded')
                done({ message: 'API quota exceeded', err: err });
                return;
            }

            if (err && err.statusCode !== 404) {
                Logger.error('error looking up entity', { entity: entity });
                done(err);
                return;
            }

            let risk = data.data.risk;

            results.push({
                entity: entity,
                data: {
                    summary: [
                        risk.criticalityLabel,
                        `Risk Score: ${risk.score}`,
                        `Rules: ${risk.riskString}`
                    ],
                    details: data.data
                }
            });
            done();
        });
    }, err => {
        if (err) {
            Logger.error('Error during lookup', { err: err });
        }

        callback(err, results);
    });
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
    if (typeof options[optionName].value !== 'string' ||
        (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)) {
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
