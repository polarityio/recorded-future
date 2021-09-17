const nock = require('nock');
const { doLookup, startup } = require('../integration');
const options = {
  apiKey: '12345',
  minimumScore: 0,
  domainBlocklistRegex: '',
  ipBlocklistRegex: '',
  blocklist: '',
  maxConcurrent: 10,
  minTime: 1
};

const ip = {
  type: 'IPv4',
  value: '8.8.8.8',
  isPrivateIP: false,
  isIPv4: true,
  isIP: true
};

const Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.info(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

beforeAll(() => {
  startup(Logger);
})

test('502 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock('https://api.recordedfuture.com').get(/.*/).reply(502);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.general.maxRequestQueueLimitHit).toBe(false);
    expect(details.general.isConnectionReset).toBe(false);
    expect(details.general.isGatewayTimeout).toBe(true);
    done();
  });
});

test('504 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock('https://api.recordedfuture.com').get(/.*/).reply(504);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.general.maxRequestQueueLimitHit).toBe(false);
    expect(details.general.isConnectionReset).toBe(false);
    expect(details.general.isGatewayTimeout).toBe(true);
    done();
  });
});

test('ECONNRESET response should result in `isConnectionReset`', (done) => {
  const scope = nock('https://api.recordedfuture.com').get(/.*/).replyWithError({code: 'ECONNRESET'});
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.general.maxRequestQueueLimitHit).toBe(false);
    expect(details.general.isConnectionReset).toBe(true);
    expect(details.general.isGatewayTimeout).toBe(false);
    done();
  });
});

test('500 response should return a normal integration error', (done) => {
  const scope = nock('https://api.recordedfuture.com').get(/.*/).reply(500);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(err[0], null, 4));
    expect(err.length).toBe(1);
    expect(err[0].err.statusCode).toBe(500);
    done();
  });
});
