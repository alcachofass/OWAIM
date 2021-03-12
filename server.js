const Net = require('net');
const Options = require('./options.js');
const SessionManager = require('./sessionmanager.js');
const User = require('./user.js');
const Util = require('./util.js');
const extend = require('extend');

let options = new Options();
let sessionManager = new SessionManager();

let auth = Net.createServer(function (socket) {
    console.log('<+> client connected to auth.');
    let session = sessionManager.add({ socket: socket });
    session.socket.on('end', function () {
        console.log('<-> client disconnected from auth.');
        session.socket = undefined;
        session.sequence = undefined;
        if (!session.user) {
            sessionManager.remove(session);
        }
    });
    session.socket.on('data', function (data) {
        var _bytes = Util.Bit.BufferBytes(data);
        if (_bytes.length < 10) { return; }
        while (_bytes.length > 0) {
            if (_bytes.slice(0, 1)[0] !== 42) {
                console.log('<!> non FLAP packet.');
                return;
            }
            var size = Util.Bit.BytesToUInt16(_bytes.slice(4, 6));
            ProcessAuthRequest(session, _bytes.slice(0, 6), _bytes.slice(6, 6 + size), _bytes.splice(0, 6 + size));
        }
    });
    SendData(session, 0, 1, Util.Constants._FLAP_VERSION);
});
auth.listen(options.authPort, options.ip);
console.log('Auth socket listening on port', options.authPort);

let bos = Net.createServer(function (socket) {
    console.log('<+> client connected to auth.');
    let session = sessionManager.add({ socket: socket });
    session.socket.on('end', function () {
        console.log('<-> client disconnected from bos.');
        session.socket = undefined;
        session.sequence = undefined;
        sessionManager.remove(session);
    });
    session.socket.on('data', function (data) {
        var _bytes = Util.Bit.BufferBytes(data);
        if (_bytes.length < 10) { return; }
        while (_bytes.length > 0) {
            if (_bytes.slice(0, 1)[0] !== 42) {
                console.log('<!> non FLAP packet.');
                return;
            }
            var size = Util.Bit.BytesToUInt16(_bytes.slice(4, 6));
            ProcessBosRequest(session, _bytes.slice(0, 6), _bytes.slice(6, 6 + size), _bytes.splice(0, 6 + size));
        }
    });
    SendData(session, 0, 1, Util.Constants._FLAP_VERSION);
});
bos.listen(options.bosPort, options.ip);
console.log('BOS socket listening on port', options.bosPort);

async function ProcessAuthRequest(session, flap, data, bytes) {
    let FLAP = Util.AIMPackets.GetFLAP(flap);
    if (FLAP.channel === 2) {
        let SNAC = Util.AIMPackets.GetSNAC(data);
        // Bucp Challenge Request
        if (SNAC.foodGroup === 17 && SNAC.type === 6) {
            let user = new User();
            await user.init(SNAC.tlvs['0x01'].data);
            console.log(['--> challenge request recieved for "', SNAC.tlvs['0x01'].data, '".'].join(''));
            if (user.Screenname !== SNAC.tlvs['0x01'].data) {
                console.log(['<!> screenname "', SNAC.tlvs['0x01'].data, '" does not exist.'].join(''));
                SendData(session, 0, 2, Util.AIMPackets.CreateBucpResponse({ screenName: SNAC.tlvs['0x01'].data, badLogin: true, url: 'https://www.oceanandwith.com/owaim/unregistered', error: 1 }));
                user = null;
                return;
            }
            if (user.Deleted) {
                console.log(['<!> screenname "', SNAC.tlvs['0x01'].data, '" deleted.'].join(''));
                SendData(session, 0, 2, Util.AIMPackets.CreateBucpResponse({ screenName: SNAC.tlvs['0x01'].data, badLogin: true, url: 'https://www.oceanandwith.com/owaim/deleted', error: 8 }));
                user = null;
                return;
            }
            if (user.Suspended) {
                console.log(['<!> screenname "', snac.tlvs['0x01'].data, '" suspended.'].join(''));
                SendData(session, 0, 2, Util.AIMPackets.CreateBucpResponse({ screenName: SNAC.tlvs['0x01'].data, badLogin: true, url: 'https://www.oceanandwith.com/owaim/suspended', error: 17 }));
                user = null;
                return;
            }
            session.ticket = Util.Strings.GenerateTicket();
            SendData(session, 0, 2, Util.AIMPackets.CreateBucpChallenge(session.ticket));
            console.log(['<-- sent bucp_challenge to "', SNAC.tlvs['0x01'].data, '".'].join(''));
            return;
        }
        // Bucp Challenge Response
        if (SNAC.foodGroup === 17 && SNAC.type === 2) {
            let user = new User();
            await user.init(SNAC.tlvs['0x01'].data);
            console.log(['--> challenge response recieved for "', SNAC.tlvs['0x01'].data, '".'].join(''));
            if (SNAC.tlvs['0x25'] !== null) {
                let check = Util.Strings.CheckPassword(session.ticket, user.Password, SNAC.tlvs['0x25'].data);
                console.log('<.> password check:', check);
                if (check) {
                    let cookie = Util.Strings.GenerateCookie();
                    session.cookie = Util.Strings.BytesToHexString(Util.Bit.BufferBytes(cookie));
                    session.user = user;
                    SendData(session, 0, 2, Util.AIMPackets.CreateBucpResponse({ screenName: session.user.Screenname, bosHost: options.ip, bosPort: options.bosPort, passwordChangeURL: 'https://www.oceanandwith.com/owaim/password', emailAddress: user.EmailAddress, cookie: cookie }));
                    console.log(['<-- sent bucp_response to "', SNAC.tlvs['0x01'].data, '".'].join(''));
                    return;
                }
                SendData(session, 0, 2, Util.AIMPackets.CreateBucpResponse({ screenName: SNAC.tlvs['0x01'].data, badLogin: true, url: 'https://www.oceanandwith.com/owaim/password', error: 5 }));
                console.log(['<-- sent bucp_response to "', SNAC.tlvs['0x01'].data, '".'].join(''));
                return;
            }
            return;
        }
        // All other SNACs
        console.log('unhandled SNAC:', SNAC);
        return;
    }
    if (FLAP.channel === 4) {
        session.socket.close();
        console.log('<!> connection reset.');
        return;
    }
}

async function ProcessBosRequest(session, flap, data, bytes) {
    let FLAP = Util.AIMPackets.GetFLAP(flap);
    if (FLAP.channel === 1) {
        console.log('--> auth request recieved.');
        if (data.length > 4) {
            console.log('--> recieved authentication cookie.');
            let cookie = Util.AIMPackets.GetTLVs(data.slice(4));
            var existingSession = sessionManager.item({ cookie: cookie['0x06'].data });
            if (existingSession) {
                extend(session, existingSession) && sessionManager.remove(existingSession) && console.log(['</> session reconciliation for "', session.user.Screenname, '".'].join(''));
                SendData(session, 0, 2, Util.AIMPackets.CreateServerHostOnline());
                console.log('<-- sent server_host_online.');
            } else {
                console.log('<!> authentication cookie not found.');
                SendData(session, 0, 4, []);
                console.log('<-- sent punt. goodbye.');
            }
        }
    }
    if (FLAP.channel === 2) {
        let SNAC = Util.AIMPackets.GetSNAC(data);
        if (SNAC.foodGroup === 1 && SNAC.type === 2) {
            console.log(['--> ', session.user.Screenname, ' has signed on successfully.'].join(''));
            session.user.SignedOn = true;
            session.user.SignedOnTimestamp = Math.floor(new Date().getTime() / 1000);
            session.user.updateStatus(session, sessionManager, SendData);
            return;
        }
        if (SNAC.foodGroup === 1 && SNAC.type === 4) {
            console.log(['--> recieved service request for group ', SNAC.groupId, '.'].join(''));
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateServiceResponse(options.ip, options.aosPort, SNAC.groupId, Util.Strings.BytesToHexString(Util.Bit.BufferBytes(Util.Strings.GenerateCookie()))));
            console.log(['<-- sent service request for group ', SNAC.groupId, '.'].join(''));
            return;
        }
        if (SNAC.foodGroup === 1 && SNAC.type === 6) {
            console.log('--> recieved request for rate limits.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateServiceRateLimitsResponse());
            console.log('<-- sent service_rate_limits.');
            return;
        }
        if (SNAC.foodGroup === 1 && SNAC.type === 8) {
            console.log('--> recieved rate limits acceptance.', SNAC.rateLimits);
            return;
        }
        if (SNAC.foodGroup === 1 && SNAC.type === '0e') {
            console.log('--> recieved request for self.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateSelfInfoResponse(session.user.FormattedScreenname));
            console.log('<-- sent self_info_response.');
            return;
        }
        if (SNAC.foodGroup === 1 && SNAC.type === 17) {
            console.log('--> recieved request for service host versions.');
            SendData(session, 0, 2, Util.AIMPackets.CreateServiceHostVersions());
            console.log('<-- sent service_host_versions.');
            SendData(session, 0, 2, Util.AIMPackets.CreateServiceMOTD());
            console.log('<-- sent serivce_motd.');
            return;
        }
        if (SNAC.foodGroup === 2 && SNAC.type === 2) {
            console.log('--> recieved location rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateLocationRightsResponse());
            console.log('<-- sent location rights response.');
            return;
        }
        if (SNAC.foodGroup === 2 && SNAC.type === 4) {
            console.log('--> recieved user location information.');
            Object.keys(SNAC.tlvs).forEach(function (item) {
                switch (item) {
                    case '0x01':
                        session.user.ProfileEncoding = SNAC.tlvs[item].data;
                        console.log('<+> set user profile encoding.');
                        break;
                    case '0x02':
                        session.user.Profile = SNAC.tlvs[item].data;
                        console.log('<+> set user profile.');
                        break;
                    case '0x03':
                        session.user.AwayMessageEncoding = SNAC.tlvs[item].data;
                        console.log('<+> set user away message encoding.');
                        break;
                    case '0x04':
                        session.user.AwayMessage = SNAC.tlvs[item].data;
                        console.log('<+> set user away message.');
                        break;
                    case '0x05':
                        session.user.Capabilities = SNAC.tlvs[item].data;
                        console.log('<+> set user capabilities.');
                        break;
                    case '0x06':
                        session.user.Certs = SNAC.tlvs[item].data;
                        console.log('<+> set user certs.');
                        break;
                }
            });
            return;
        }
        if (SNAC.foodGroup === 2 && SNAC.type === '0b') {
            console.log('--> recieved locate directory info request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateLocateDirectoryInfoResponse());
            console.log('<-- sent locate directory info response.');
            return;
        }
        if (SNAC.foodGroup === 3 && SNAC.type === 2) {
            console.log('--> recieved buddy rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyRightsResponse());
            console.log('<-- sent buddy rights response.');
            return;
        }
        if (SNAC.foodGroup === 4 && SNAC.type === 4) {
            console.log('--> recieved icbm params request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateIcbmParamsResponse());
            console.log('<-- sent icbm params response.');
            return;
        }
        if (SNAC.foodGroup === 7 && SNAC.type === 2) {
            console.log('--> recieved admin info request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === 7 && SNAC.type === 4) {
            console.log('--> recieved admin info update request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === 9 && SNAC.type === 2) {
            console.log('--> recieved bos rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateBosRightsResponse());
            console.log('<-- sent bos rights response.');
            return;
        }

        if (SNAC.foodGroup === 13 && SNAC.type === 2) {
            console.log('--> recieved feedbag rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagRightsResponse());
            console.log('<-- sent feedbag rights response.');
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === 4) {
            console.log('--> recieved feedbag buddylist request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyListResponse(session.user.buddyList, session.user.FeedbagTimestamp));
            console.log('<-- sent feedbag buddylist response.');
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === 5) {
            console.log('--> recieved feedbag buddylist request if_modified*.');
            console.log('<.> comparing db:', session.user.FeedbagTimestamp, ', client:', SNAC.date);
            if (session.user.FeedbagTimestamp > SNAC.date) {
                console.log('<.> db buddy list is newer.');
                SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyListResponse(session.user.buddyList, session.user.FeedbagTimestamp).concat(Util.Bit.UInt32ToBytes(SNAC.date + 2588)));
                console.log('<-- sent feedbag buddylist modified* response.');
                console.log(session.user.buddyList);
            } else {
                console.log('<.> client buddy list is newer.');
                SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyListNotModifiedResponse(SNAC.date, SNAC.count));
                console.log('<-- sent feedbag buddylist not_modified* response.');
            }
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === 7) {
            console.log(['--> ', session.user.Screenname, ' has recieved their buddy list.'].join(''));
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === 8) {
            console.log('--> recieved feedbag add request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === 9) {
            console.log('--> recieved feedbag update request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === '0a') {
            console.log('--> recieved feedbag deleted request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === 13 && SNAC.type === 12) {
            console.log('--> recieved feedbag modify_complete*.');
            console.log('unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === '0d' && SNAC.type === 2) {
            console.log('--> recieved chav_nav rights request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        if (SNAC.foodGroup === '0d' && SNAC.type === 8) {
            console.log('--> recieved room create request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }
        // all other SNAC
        console.log('unhandled SNAC:', SNAC);
        return;
    }
    if (FLAP.channel === 4) {
        session.socket.close();
        console.log('<!> connection reset.');
        return;
    }
}

function SendData(session, requestId, channel, bytes, replay) {
    session.sequence++;
    if (session.sequence === 65535) { session.sequence = 0; }
    if (channel === 2) {
        if (requestId > 0) {
            bytes.splice(6, 4, ...Util.Bit.UInt32ToBytes(requestId));
        }
    }
    var packet = Util.AIMPackets.CreateFLAP(channel, session.sequence, bytes);
    session.socket.write(packet);
    if (replay) {
        console.log(JSON.stringify(b));
    }
}