let assert = require('chai').assert;
let bunyan = require('bunyan');

let integration = require('./integration');
let config = require('./config/config');
config.request.rejectUnauthorized = false;

describe('Recorded Future integration', () => {
  before(() => {
    integration.startup(bunyan.createLogger({ name: 'test logger', level: bunyan.TRACE }));
  });

  it('should show a quota exceeded error when response is a 403', (done) => {
    integration.doLookup(
      [
        {
          value: '10.10.10.10',
          isIP: true
        }
      ],
      {
        host: 'https://localhost:5555',
        domainBlacklistRegex: '',
        blacklist: '',
        ipBlacklistRegex: ''
      },
      (err, resp) => {
        assert.isOk(err);
        assert.equal(err.message, 'API quota exceeded');
        done();
      }
    );
  });
});
