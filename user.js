const Database = require('./db.js');
const extend = require('extend');
const Util = require('./util.js');

var db = new Database();

module.exports = class User {
    constructor() {
    }
    async init(screenName) {
        var b = await db.getMembership(screenName);
        extend(this, b);
        var c = await db.getBuddyList(this.ID);
        this.buddyList = c;
    }
    async updateStatus(session, sessionManager, sendDataCallback) {
        var $this = this;
        var onBuddyList = await db.getOnBuddyList(this.Screenname);
        var foundSessions = sessionManager.collection().filter(function (item) { return onBuddyList.indexOf(item.user.ID) > -1; });
        foundSessions.forEach(function (item) {
            if (this.SignedOn) {
                sendDataCallback(item, 0, 2, Util.AIMPackets.CreateBuddyArrived(this.Screenname, this.SignedOnTimestamp, this.Capabilities));
            } else {
                sendDataCallback(item, 0, 2, Util.AIMPackets.CreateBuddyDeparted(this.Screenname));
            }
        });
        var sessionsFound = sessionManager.collection().filter(function (item) { return $this.buddyList.find(function (i) { return i.Name === item.user.Screenname && i.ClassID === 0 }); });
        sessionsFound.forEach(function (item) {
            if (item.SignedOn) {
                sendDataCallback(session, 0, 2, Util.AIMPackets.CreateBuddyArrived(item.Screenname, item.SignedOnTimestamp, item.Capabilities));
            } else {
                sendDataCallback(session, 0, 2, Util.AIMPackets.CreateBuddyDeparted(item.Screenname));
            }
        });
    }
}