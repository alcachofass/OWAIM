const sql = require('sqlite3').verbose();
class Database {
    constructor() {
        this.db = new sql.Database('./owaim.db');
    }
    getMembership(screenName) {
        var $this = this;
        return new Promise(function (resolve, reject) {
            $this.db.get(['SELECT * FROM Memberships WHERE Screenname = \'', screenName, '\''].join(''), function (err, row) {
                resolve(row ? {
                    ID: row.ID,
                    Screenname: row.Screenname,
                    FormattedScreenname: row.FormattedScreenname,
                    Password: row.Password,
                    TemporaryEvil: row.TemporaryEvil,
                    PermanentEvil: row.PermanentEvil,
                    EmailAddress: row.EmailAddress,
                    Confirmed: row.Confirmed,
                    Internal: row.Internal,
                    Suspended: row.Suspended,
                    Deleted: row.Deleted,
                    Notes: row.Notes,
                    LastSignonDate: row.LastSignonDate,
                    CreationDate: row.CreationDate,
                    LoggedIPAddresses: row.LoggedIPAddresses,
                    RegisteredIPAddress: row.RegisteredIPAddress,
                    FeedbagTimestamp: row.FeedbagTimestamp,
                    FeedbagItems: row.FeedbagItems
                } : null);
            });
        });
    }
    getBuddyList(id) {
        var $this = this;
        return new Promise(function (resolve, reject) {
            var rows = [];
            $this.db.each(['SELECT * FROM Feedbag WHERE [ID] = ?'].join(''), id, function (err, row) {
                rows.push({ PID: row.PID, ID: row.ID, Name: row.Name, GroupID: row.GroupID, BuddyID: row.BuddyID, ClassID: row.ClassID, Attributes: row.Attributes });
            }, function () {
                if (!rows.length) {
                    // Master group.
                    $this.db.run(['INSERT INTO Feedbag (ID, Name, GroupID, BuddyID, ClassID, Attributes) VALUES (?, ?, ?, ?, ?, ?)'].join(''), id, '', 0, 0, 1, Buffer.from([0x00, 0xc8, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]), function () {
                        // Buddy preferences.
                        $this.db.run(['INSERT INTO Feedbag (ID, Name, GroupID, BuddyID, ClassID, Attributes) VALUES (?, ?, ?, ?, ?, ?)'].join(''), id, '', 0, 1, 5, Buffer.from([0x00, 0xc9, 0x00, 0x04, 0x00, 0x61, 0xe7, 0xff, 0x00, 0xd6, 0x00, 0x04, 0x00, 0x77, 0xff, 0xff]), function () {
                            // Buddies group.
                            $this.db.run(['INSERT INTO Feedbag (ID, Name, GroupID, BuddyID, ClassID, Attributes) VALUES (?, ?, ?, ?, ?, ?)'].join(''), id, 'Buddies', 1, 0, 1, '', function () {
                                // Family group.
                                $this.db.run(['INSERT INTO Feedbag (ID, Name, GroupID, BuddyID, ClassID, Attributes) VALUES (?, ?, ?, ?, ?, ?)'].join(''), id, 'Family', 2, 0, 1, '', function () {
                                    // Co-Workers group.
                                    $this.db.run(['INSERT INTO Feedbag (ID, Name, GroupID, BuddyID, ClassID, Attributes) VALUES (?, ?, ?, ?, ?, ?)'].join(''), id, 'Co-Workers', 3, 0, 1, '', function () {
                                        let timestamp = Math.round(new Date().getTime() / 1000);
                                        // Update user.
                                        $this.db.run(['UPDATE Memberships SET [FeedbagTimestamp] = ?, [FeedbagItems] = 5 WHERE [ID] = ?'].join(''), timestamp, id, function () {
                                            // reload
                                            $this.db.each(['SELECT * FROM Feedbag WHERE [ID] = ?'].join(''), id, function (err, row) {
                                                rows.push({ PID: row.PID, ID: row.ID, Name: row.Name, GroupID: row.GroupID, BuddyID: row.BuddyID, ClassID: row.ClassID, Attributes: row.Attributes });
                                            }, function () { resolve({ timestamp: timestamp, rows: rows}); });
                                        });
                                    });
                                });
                            });
                        });
                    });
                } else {
                    resolve(rows);
                }
            });
        });
    }
    getOnBuddyList(screenName) {
        var $this = this;
        return new Promise(function (resolve, reject) {
            var rows = []
            $this.db.each('SELECT * FROM Feedbag WHERE Name = ? AND ClassID = 0', screenName, function (err, row) {
                rows.push(row.ID);
            }, function () {
                    resolve(rows);
            });
        });
    }
}
module.exports = Database;
