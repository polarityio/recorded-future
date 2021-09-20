polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  summary: Ember.computed.alias('block.data.summary'),

  redThreat: '#fa5843',
  greenThreat: '#7dd21b',
  yellowThreat: '#ffc15d',
  /**
   * Radius of the ticScore circle
   */
  threatRadius: 15,
  /**
   * StrokeWidth of the ticScore circle
   */
  threatStrokeWidth: 2,
  elementRadius: 20,
  elementStrokeWidth: 4,

  elementColor: Ember.computed('details.risk.score', function () {
    return this._getThreatColor(this.get('details.risk.score'));
  }),
  elementStrokeOffset: Ember.computed('details.risk.score', 'elementCircumference', function () {
    return this._getStrokeOffset(this.get('details.risk.score'), this.get('elementCircumference'));
  }),

  threatCircumference: Ember.computed('threatRadius', function () {
    return 2 * Math.PI * this.get('threatRadius');
  }),
  elementCircumference: Ember.computed('elementRadius', function () {
    return 2 * Math.PI * this.get('elementRadius');
  }),
  _getStrokeOffset(ticScore, circumference) {
    let progress = ticScore / 100;
    return circumference * (1 - progress);
  },
  _getThreatColor(ticScore) {
    if (ticScore >= 75) {
      return this.get('redThreat');
    } else if (ticScore >= 50) {
      return this.get('yellowThreat');
    } else {
      return this.get('greenThreat');
    }
  },
  searchLink: Ember.computed('block.entity.value','block.entity.type', function(){
    const type = this.get('block.entity.type');
    const value = this.get('block.entity.value');
    switch(type){
      case 'IPv4':
        return `https://app.recordedfuture.com/live/sc/entity/ip%3A${value}`
        break;
      case 'url':
        return `https://app.recordedfuture.com/live/sc/entity`
        break;
      case 'domain':
        return `https://app.recordedfuture.com/live/sc/entity/idn%3A${value.toLowerCase()}`
        break;
      case 'hash':
        return `https://app.recordedfuture.com/live/sc/entity/hash%3A${value.toLowerCase()}`
        break;
      case 'cve':
        return 'https://app.recordedfuture.com/live/sc/entity'
        break;
      default:
        return 'https://app.recordedfuture.com/live/sc/entity'
    }
  }),
  hasLocation: Ember.computed('block.data.details', function () {
    let details = this.get('block.data.details');
    if (details.location && details.location.location) {
      if (details.location.location.country) {
        return true;
      }
      if (details.location.location.city) {
        return true;
      }
      if (details.location.organization) {
        return true;
      }
    }
    return false;
  }),
  hasSighting: Ember.computed('block.data.details.sightings', function () {
    return !!this.get('block.data.details.sightings');
  }),
  hasLink: Ember.computed('block.data.details.intelCard', function () {
    return !!this.get('block.data.details.intelCard');
  }),
  actions: {
    retryLookup: function () {
      this.set('running', true);
      this.set('errorMessage', '');
      const payload = {
        action: 'RETRY_LOOKUP',
        entity: this.get('block.entity')
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set('summary', result.summary);
          this.set('block.data', result.data);
        })
        .catch((err) => {
          this.set('details.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    }
  }
});
