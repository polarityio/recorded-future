polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),

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

    elementColor: Ember.computed('details.ticScore', function(){
        return this._getThreatColor(this.get('details').risk.score);
    }),
    elementStrokeOffset: Ember.computed('details.ticScore', 'elementCircumference', function(){
        return this._getStrokeOffset(this.get('details').risk.score, this.get('elementCircumference'));
    }),

    threatCircumference: Ember.computed('threatRadius', function () {
        return 2 * Math.PI * this.get('threatRadius');
    }),
    elementCircumference: Ember.computed('elementCircumference', function(){
        return 2 * Math.PI * this.get('elementRadius');
    }),
    _getStrokeOffset(ticScore, circumference){
        let progress = ticScore / 100;
        return circumference * (1 - progress);
    },
    _getThreatColor(ticScore){
        if (ticScore >= 75) {
            return this.get('redThreat');
        } else if (ticScore >= 50) {
            return this.get('yellowThreat');
        } else {
            return this.get('greenThreat');
        }
    },

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
