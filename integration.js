let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;
let requestWithDefaults;
let requestOptions = {};

function handleRequestError(request) {
    return (options, expectedStatusCode, callback) => {
        return request(options, (err, resp, body) => {
            if (err || resp.statusCode !== expectedStatusCode) {
                Logger.error(`error during http request to ${options.url}`, { error: err, status: resp ? resp.statusCode : 'unknown' });
                callback({ error: err, statusCode: resp ? resp.statusCode : 'unknown' });
            } else {
                callback(null, body);
            }
        });
    };
}

function doLookup(entities, options, callback) {
    Logger.trace('looking entities');

    let results = [];

    async.forEach(entities, (entity, done) => {
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
            requestOptions.url = 'https://api.recordedfuture.com/v2/ip/' + entity.value;
            requestOptions.qs.fields = requestOptions.qs.fields
                .split(',')
                .concat('location')
                .join(',');
        } else if (entity.isHash) {
            requestOptions.url = 'https://api.recordedfuture.com/v2/hash/' + entity.value;
        } else if (entity.isDomain) {
            requestOptions.url = 'https://api.recordedfuture.com/v2/domain/' + entity.value;
        } else if (entity.isURL) {
            requestOptions.url = 'https://api.recordedfuture.com/v2/url/' + encodeURIComponent(entity.value);
        } else {
            done({ err: new Error('unknown entity type') });
            return
        }

        requestWithDefaults(requestOptions, 200, (err, data) => {
            if (err && err.statusCode !== 404) {
                Logger.error('error looking up entity', { entity: entity });
                done(err);
                return;
            }

            if ((err && err.statusCode === 404) || data.data.risk.score < options.minimumScore) {
                results.push({
                    entity: entity,
                    data: null
                });
                done();
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
