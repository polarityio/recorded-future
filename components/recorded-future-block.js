polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    hasLocation: Ember.computed('block.data.details', function () {
        let data = this.get('block.data.details');
        return !!data.location;
    }),
    hasSighting: Ember.computed('block.data.details', function () {
        let data = this.get('block.data.details');
        return !!data.sightings;
    }),
    hasLink: Ember.computed('block.data.details', function () {
        let data = this.get('block.data.details');
        return !!data.intelCard;
    })
});
