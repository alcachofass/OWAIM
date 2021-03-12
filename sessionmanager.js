const extend = require('extend');

module.exports = class SessionManager {
    #collection;
    constructor() {
        this.#collection = [];
    }
    add(item) {
        var b = extend(true, {}, { sequence: 0 }, item);
        this.#collection.push(b);
        return b;
    }
    remove(item) {
        if (typeof item === 'string') {
            var a = this.#collection.find(function (i) { return i.screenName === item; });
            if (a.length) {
                this.#collection.splice(this.#collection.indexOf(a[0]), 1);
            }
            return this;
        }
        this.#collection.splice(this.#collection.indexOf(item), 1);
        return this;
    }
    item({ screenName, ticket, cookie } = {}) {
        return screenName ? this.#collection.find(function (item) { return item.screenName === screenName; }) : ticket ? this.#collection.find(function (item) { return item.ticket === ticket; }) : cookie ? this.#collection.find(function (item) { return item.cookie === cookie; }) : null;
    }
    collection() {
        return this.#collection;
    }
}