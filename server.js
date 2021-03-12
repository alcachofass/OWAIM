const Net = require('net');
const Options = require('./options.js');
const SessionManager = require('./sessionmanager.js');
const User = require('./user.js');
const Util = require('./util.js');
const extend = require('extend');

let options = new Options();
let sessionManager = new SessionManager();

// create a new socket server using ip and port from options.
let auth = Net.createServer(function (socket) {
    console.log('<+> client connected to auth.');
    // add socket to session manager.
    let session = sessionManager.add({ socket: socket });
    // event handler: end
    session.socket.on('end', function () {
        console.log('<-> client disconnected from auth.');
        // unbind socket.
        session.socket = undefined;
        // reset sequence.
        session.sequence = undefined;
        // check for existence of user object in session.
        if (!session.user) {
            // remove the session from session manager if user hasn't been set.
            sessionManager.remove(session);
        }
    });
    // event handler: data
    session.socket.on('data', function (data) {
        // get bytes from buffer.
        var _bytes = Util.Bit.BufferBytes(data);
        // check if byte length is less than 10.
        if (_bytes.length < 10) { return; } // discard if less than 10.
        while (_bytes.length > 0) {
            // check FLAP 'start' bit.
            if (_bytes.slice(0, 1)[0] !== 42) {
                console.log('<!> non FLAP packet.');
                return; // discard if not 0x2a (42);
            }
            // get payload size.
            var size = Util.Bit.BytesToUInt16(_bytes.slice(4, 6));
            // send to auth processor.
            ProcessAuthRequest(session, _bytes.slice(0, 6), _bytes.slice(6, 6 + size), _bytes.splice(0, 6 + size));
        }
    });
    // always send a channel 1 flap version packet on connect.
    SendData(session, 0, 1, Util.Constants._FLAP_VERSION);
});

// initiate listen on auth socket server.
auth.listen(options.authPort, options.ip);
console.log('Auth socket listening on port', options.authPort);

// create a new socket server using ip and port from options.
let bos = Net.createServer(function (socket) {
    console.log('<+> client connected to auth.');
    // add socket to session manager.
    let session = sessionManager.add({ socket: socket });
    // event handler: end
    session.socket.on('end', function () {
        console.log('<-> client disconnected from bos.');
        // unbind socket.
        session.socket = undefined;
        // reset sequence.
        session.sequence = undefined;
        // remove session from session manager.
        sessionManager.remove(session);
    });
    // event handler: data
    session.socket.on('data', function (data) {
        // get bytes from buffer.
        var _bytes = Util.Bit.BufferBytes(data);
        // check if byte length is less than 10.
        if (_bytes.length < 10) { return; } // discard if less than 10.
        while (_bytes.length > 0) {
            // check FLAP 'start' bit.
            if (_bytes.slice(0, 1)[0] !== 42) {
                console.log('<!> non FLAP packet.');
                return; // discard if not 0x2a (42);
            }
            // get payload size.
            var size = Util.Bit.BytesToUInt16(_bytes.slice(4, 6));
            // send to bos processor.
            ProcessBosRequest(session, _bytes.slice(0, 6), _bytes.slice(6, 6 + size), _bytes.splice(0, 6 + size));
        }
    });
    // always send a channel 1 flap version packet on connect.
    SendData(session, 0, 1, Util.Constants._FLAP_VERSION);
});

// initiate listen on bos socket server.
bos.listen(options.bosPort, options.ip);
console.log('BOS socket listening on port', options.bosPort);

async function ProcessAuthRequest(session, flap, data, bytes) {
    // get FLAP header.
    let FLAP = Util.AIMPackets.GetFLAP(flap);

    if (FLAP.channel === 2) {
        // get SNAC.
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
                // check password on TLV 0x25 against database password.
                let check = Util.Strings.CheckPassword(session.ticket, user.Password, SNAC.tlvs['0x25'].data);
                console.log('<.> password check:', check);
                if (check) { // check success.
                    let cookie = Util.Strings.GenerateCookie();
                    session.cookie = Util.Strings.BytesToHexString(Util.Bit.BufferBytes(cookie));
                    session.user = user;
                    SendData(session, 0, 2, Util.AIMPackets.CreateBucpResponse({ screenName: session.user.Screenname, bosHost: options.ip, bosPort: options.bosPort, passwordChangeURL: 'https://www.oceanandwith.com/owaim/password', emailAddress: user.EmailAddress, cookie: cookie }));
                    console.log(['<-- sent bucp_response to "', SNAC.tlvs['0x01'].data, '".'].join(''));
                    return;
                }
                // password check failed.
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
    // get FLAP header.
    let FLAP = Util.AIMPackets.GetFLAP(flap);

    if (FLAP.channel === 1) {
        console.log('--> auth request recieved.');
        // check for existence of cookie.
        if (data.length > 4) {
            console.log('--> recieved authentication cookie.');
            let cookie = Util.AIMPackets.GetTLVs(data.slice(4));
            // find existing session in session manager using cookie.
            var existingSession = sessionManager.item({ cookie: cookie['0x06'].data });
            if (existingSession) {
                // reconile existing session from session manager.
                extend(session, existingSession) && sessionManager.remove(existingSession) && console.log(['</> session reconciliation for "', session.user.Screenname, '".'].join(''));
                // expect: 0x00 0x01 0x00 0x03
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
        // SNACs come in on channel 2.
        let SNAC = Util.AIMPackets.GetSNAC(data);

        // expect: 0x00 0x01 0x00 0x02
        // service client ready.
        if (SNAC.foodGroup === 1 && SNAC.type === 2) {
            console.log(['--> ', session.user.Screenname, ' has signed on successfully.'].join(''));
            // set SignedOn on user object in session manager.
            session.user.SignedOn = true;
            // set SignedOnTimestamp on user object in session manager.
            session.user.SignedOnTimestamp = Math.floor(new Date().getTime() / 1000);
            session.user.updateStatus(session, sessionManager, SendData);
            return;
        }

        // expect: 0x00 0x01 0x00 0x04
        // service request.
        if (SNAC.foodGroup === 1 && SNAC.type === 4) {
            console.log(['--> recieved service request for group ', SNAC.groupId, '.'].join(''));
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateServiceResponse(options.ip, options.aosPort, SNAC.groupId, Util.Strings.BytesToHexString(Util.Bit.BufferBytes(Util.Strings.GenerateCookie()))));
            console.log(['<-- sent service request for group ', SNAC.groupId, '.'].join(''));
            return;
        }

        // expect: 0x00 0x01 0x00 0x06
        // request rate limits.
        if (SNAC.foodGroup === 1 && SNAC.type === 6) {
            console.log('--> recieved request for rate limits.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateServiceRateLimitsResponse());
            console.log('<-- sent service_rate_limits.');
            return;
        }

        // expect: 0x00 0x01 0x00 0x08
        // rate limits acceptance.
        if (SNAC.foodGroup === 1 && SNAC.type === 8) {
            console.log('--> recieved rate limits acceptance.', SNAC.rateLimits);
            return;
        }

        // expect: 0x00 0x01 0x00 0x0e
        // self request.
        if (SNAC.foodGroup === 1 && SNAC.type === '0e') {
            console.log('--> recieved request for self.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateSelfInfoResponse(session.user.FormattedScreenname));
            console.log('<-- sent self_info_response.');
            return;
        }

        // expect: 0x00 0x01 0x00 0x17
        // service host versions request.
        if (SNAC.foodGroup === 1 && SNAC.type === 17) {
            console.log('--> recieved request for service host versions.');
            SendData(session, 0, 2, Util.AIMPackets.CreateServiceHostVersions());
            console.log('<-- sent service_host_versions.');
            SendData(session, 0, 2, Util.AIMPackets.CreateServiceMOTD());
            console.log('<-- sent serivce_motd.');
            return;
        }

        // expect: 0x00 0x02 0x00 0x02
        // location rights request.
        if (SNAC.foodGroup === 2 && SNAC.type === 2) {
            console.log('--> recieved location rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateLocationRightsResponse());
            console.log('<-- sent location rights response.');
            return;
        }

        // expect: 0x00 0x02 0x00 0x04
        // user directory location information
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

        // expect: 0x00 0x02 0x00 0x0b
        // locate directory info request.
        if (SNAC.foodGroup === 2 && SNAC.type === '0b') {
            console.log('--> recieved locate directory info request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateLocateDirectoryInfoResponse());
            console.log('<-- sent locate directory info response.');
            return;
        }

        // expect: 0x00 0x03 0x00 0x02
        // buddy rights request.
        if (SNAC.foodGroup === 3 && SNAC.type === 2) {
            console.log('--> recieved buddy rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyRightsResponse());
            console.log('<-- sent buddy rights response.');
            return;
        }

        // expect: 0x00 0x04 0x00 0x04
        // icbm params request.
        if (SNAC.foodGroup === 4 && SNAC.type === 4) {
            console.log('--> recieved icbm params request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateIcbmParamsResponse());
            console.log('<-- sent icbm params response.');
            return;
        }

        // expect: 0x00 0x07 0x00 0x02
        // admin info request.
        // TODO: build response.
        if (SNAC.foodGroup === 7 && SNAC.type === 2) {
            console.log('--> recieved admin info request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x07 0x00 0x04
        // admin info update request.
        // TODO: ingest types and update user object and database. build response.
        if (SNAC.foodGroup === 7 && SNAC.type === 4) {
            console.log('--> recieved admin info update request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x09 0x00 0x02
        // bos rights request.
        if (SNAC.foodGroup === 9 && SNAC.type === 2) {
            console.log('--> recieved bos rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateBosRightsResponse());
            console.log('<-- sent bos rights response.');
            return;
        }

        // expect: 0x00 0x13 0x00 0x02
        // feedbag rights request.
        if (SNAC.foodGroup === 13 && SNAC.type === 2) {
            console.log('--> recieved feedbag rights request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagRightsResponse());
            console.log('<-- sent feedbag rights response.');
            return;
        }

        // expect: 0x00 0x13 0x00 0x04
        // feedbag buddylist request.
        if (SNAC.foodGroup === 13 && SNAC.type === 4) {
            console.log('--> recieved feedbag buddylist request.');
            SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyListResponse(session.user.buddyList, session.user.FeedbagTimestamp));
            console.log('<-- sent feedbag buddylist response.');
            return;
        }

        // expect: 0x00 0x13 0x00 0x05
        // feedbag buddylist request if_modified*
        if (SNAC.foodGroup === 13 && SNAC.type === 5) {
            console.log('--> recieved feedbag buddylist request if_modified*.');
            console.log('<.> comparing db:', session.user.FeedbagTimestamp, ', client:', SNAC.date);
            // check feedbag timestamp against client timestamp.
            if (session.user.FeedbagTimestamp > SNAC.date) {
                console.log('<.> db buddy list is newer.');
                // expect: 0x00 0x013 0x00 0x06
                SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyListResponse(session.user.buddyList, session.user.FeedbagTimestamp).concat(Util.Bit.UInt32ToBytes(SNAC.date + 2588)));
                console.log('<-- sent feedbag buddylist modified* response.');
                console.log(session.user.buddyList);
            } else {
                console.log('<.> client buddy list is newer.');
                // expect: 0x00 0x13 0x00 0x0f
                // sends not_modified response and echos client timestmap and feedbag item count.
                SendData(session, SNAC.requestId, 2, Util.AIMPackets.CreateFeedbagBuddyListNotModifiedResponse(SNAC.date, SNAC.count));
                console.log('<-- sent feedbag buddylist not_modified* response.');
            }
            return;
        }

        // expect: 0x00 0x13 0x00 0x07
        // feedbag in use.
        if (SNAC.foodGroup === 13 && SNAC.type === 7) {
            console.log(['--> ', session.user.Screenname, ' has recieved their buddy list.'].join(''));
            return;
        }

        // expect: 0x00 0x13 0x00 0x08
        // feedbag add request.
        // TODO: ingest feedbag items and update user object buddylist. build response.
        if (SNAC.foodGroup === 13 && SNAC.type === 8) {
            console.log('--> recieved feedbag add request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x13 0x00 0x09
        // feedbag update request.
        // TODO: ingest feedbag items and update user object buddylist. build response.
        if (SNAC.foodGroup === 13 && SNAC.type === 9) {
            console.log('--> recieved feedbag update request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x13 0x00 0x0a
        // feedbag delete request.
        // TODO: ingest feedbag items to delete and update user object. build response.
        if (SNAC.foodGroup === 13 && SNAC.type === '0a') {
            console.log('--> recieved feedbag deleted request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x13 0x00 0x12
        // feedbag modify_complete.
        // TODO: save changes to database. build response.
        if (SNAC.foodGroup === 13 && SNAC.type === 12) {
            console.log('--> recieved feedbag modify_complete*.');
            console.log('unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x0d 0x00 0x02
        // chav_nav rights request
        // TODO: build response.
        if (SNAC.foodGroup === '0d' && SNAC.type === 2) {
            console.log('--> recieved chat_nav rights request.');
            console.log('post unhandled SNAC:', SNAC);
            return;
        }

        // expect: 0x00 0x0d 0x00 0x08
        // create room request.
        // TODO: implement chatrooms. build response.
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
        // channel 4 always a graceful disconnect.
        session.socket.close();
        console.log('<!> connection reset.');
        return;
    }
}

function SendData(session, requestId, channel, bytes, replay) {
    // Bump session packet sequence.
    session.sequence++;
    // check for sequence max UInt16 value and reset.
    if (session.sequence === 65535) { session.sequence = 0; }
    // check for channel 2.
    if (channel === 2) {
        // if channel 2 ...
        if (requestId > 0) {
            // replace bit 6 through 10 with new request ID.
            bytes.splice(6, 4, ...Util.Bit.UInt32ToBytes(requestId));
        }
    }
    // build packet.
    let packet = Util.AIMPackets.CreateFLAP(channel, session.sequence, bytes);
    // write packet to session socket.
    session.socket.write(packet);
    // check for replay.
    if (replay) {
        // replay packet to the console.
        console.log('replay packet:', JSON.stringify(packet));
    }
}
