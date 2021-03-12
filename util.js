const crypto = require('crypto');

var AIMPackets = {
    CreateFLAP: function (channel, sequence, bytes) {
        return Bit.BytesBuffer(Bit.BufferBytes([0x2a]).concat(
            Bit.UInt8ToBytes(channel),
            Bit.UInt16ToBytes(sequence),
            Bit.UInt16ToBytes(bytes.length),
            bytes
        ));
    },
    CreateSNAC: function (foodGroup, type, flags, requestId) {
        return Bit.UInt16ToBytes(foodGroup).concat(Bit.UInt16ToBytes(type), Bit.UInt16ToBytes(flags), Bit.UInt32ToBytes(requestId));
    },
    CreateBucpResponse: function ({ screenName, bosPort, bosHost, passwordChangeURL, url, cookie, emailAddress, badLogin, error } = {}) {
        var SNAC = AIMPackets.CreateSNAC(0x17, 0x03, 0, 0);
        if (!badLogin) {
            return SNAC.concat(
                AIMPackets.CreateTLV(0x01, Bit.BufferBytes(screenName)),
                AIMPackets.CreateTLV(0x05, Bit.BufferBytes([bosHost, bosPort].join(':'))),
                AIMPackets.CreateTLV(0x06, Bit.BufferBytes(cookie)),
                AIMPackets.CreateTLV(0x11, Bit.BufferBytes(emailAddress)),
                AIMPackets.CreateTLV(0x54, Bit.BufferBytes(passwordChangeURL))
            );
        }
        return SNAC.concat(
            AIMPackets.CreateTLV(0x01, Bit.BufferBytes(screenName)),
            AIMPackets.CreateTLV(0x04, Bit.BufferBytes(url)),
            AIMPackets.CreateTLV(0x08, Bit.UInt16ToBytes(error))
        );
    },
    CreateBucpChallenge: function (challenge) {
        return AIMPackets.CreateSNAC(0x17, 0x07, 0, 0).concat(Bit.UInt16ToBytes(challenge.length), Bit.BufferBytes(challenge));
    },
    CreateServerHostOnline: function () {
        return AIMPackets.CreateSNAC(0x01, 0x03, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x02]),
            Bit.BufferBytes([0x00, 0x03]),
            Bit.BufferBytes([0x00, 0x04]),
            Bit.BufferBytes([0x00, 0x06]),
            Bit.BufferBytes([0x00, 0x07]),
            Bit.BufferBytes([0x00, 0x08]),
            Bit.BufferBytes([0x00, 0x09]),
            Bit.BufferBytes([0x00, 0x13])
        );
    },
    CreateServiceHostVersions: function () {
        return AIMPackets.CreateSNAC(0x01, 0x18, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x01, 0x00, 0x04]),
            Bit.BufferBytes([0x00, 0x13, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x02, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x03, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x04, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x06, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x07, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x08, 0x00, 0x01]),
            Bit.BufferBytes([0x00, 0x09, 0x00, 0x01])
        );
    },
    CreateServiceMOTD: function () {
        return AIMPackets.CreateSNAC(0x01, 0x13, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x05, 0x00, 0x02, 0x00, 0x02, 0x00, 0x1e, 0x00, 0x03, 0x00, 0x02, 0x04, 0xb0])
        );
    },
    CreateServiceRateLimitsResponse: function () {
        return AIMPackets.CreateSNAC(0x01, 0x07, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00]),
            Bit.BufferBytes([0x09, 0xc4, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x00, 0x05, 0xdc, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00]),
            Bit.BufferBytes([0x16, 0xdc, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]),
            Bit.BufferBytes([0x50, 0x00, 0x00, 0x0B, 0xB8, 0x00, 0x00, 0x07, 0xD0, 0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x03]),
            Bit.BufferBytes([0xe8, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x7b, 0x00]),
            Bit.UInt16ToBytes(3), Bit.UInt32ToBytes(1000), Bit.UInt32ToBytes(30), Bit.UInt32ToBytes(20), Bit.UInt32ToBytes(10), Bit.UInt32ToBytes(0), Bit.UInt32ToBytes(65535), Bit.UInt32ToBytes(65535), Bit.UInt32ToBytes(0), Bit.UInt8ToBytes(0),
            Bit.BufferBytes([0x00, 0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x15, 0x7C, 0x00, 0x00, 0x14, 0xB4, 0x00]),
            Bit.BufferBytes([0x00, 0x10, 0x68, 0x00, 0x00, 0x0B, 0xB8, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x1F, 0x40, 0x00]),
            Bit.BufferBytes([0x00, 0x00, 0x7B, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x15, 0x7C, 0x00, 0x00]),
            Bit.BufferBytes([0x14, 0xB4, 0x00, 0x00, 0x10, 0x68, 0x00, 0x00, 0x0B, 0xB8, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00]),
            Bit.BufferBytes([0x1F, 0x40, 0x00, 0x00, 0x00, 0x7B, 0x00, 0x00, 0x01, 0x00, 0xA6, 0x00, 0x01, 0x00, 0x01, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x09, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x0D, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x11, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x12, 0x00, 0x01, 0x00, 0x13, 0x00, 0x01, 0x00, 0x14, 0x00, 0x01, 0x00, 0x15, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x16, 0x00, 0x01, 0x00, 0x17, 0x00, 0x01, 0x00, 0x18, 0x00, 0x01, 0x00, 0x19, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x1A, 0x00, 0x01, 0x00, 0x1B, 0x00, 0x01, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x1D, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x1E, 0x00, 0x01, 0x00, 0x1F, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x21, 0x00]),
            Bit.BufferBytes([0x01, 0x00, 0x22, 0x00, 0x01, 0x00, 0x23, 0x00, 0x01, 0x00, 0x24, 0x00, 0x01, 0x00, 0x25, 0x00]),
            Bit.BufferBytes([0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x00, 0x02, 0x00, 0x04, 0x00]),
            Bit.BufferBytes([0x02, 0x00, 0x06, 0x00, 0x02, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x0A, 0x00]),
            Bit.BufferBytes([0x02, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x0D, 0x00, 0x02, 0x00, 0x0E, 0x00, 0x02, 0x00, 0x0F, 0x00]),
            Bit.BufferBytes([0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x11, 0x00, 0x02, 0x00, 0x12, 0x00, 0x02, 0x00, 0x13, 0x00]),
            Bit.BufferBytes([0x02, 0x00, 0x14, 0x00, 0x02, 0x00, 0x15, 0x00, 0x03, 0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00]),
            Bit.BufferBytes([0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x06, 0x00, 0x03, 0x00, 0x07, 0x00, 0x03, 0x00, 0x08, 0x00]),
            Bit.BufferBytes([0x03, 0x00, 0x09, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x03, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x0C, 0x00]),
            Bit.BufferBytes([0x03, 0x00, 0x0D, 0x00, 0x03, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00]),
            Bit.BufferBytes([0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x04, 0x00, 0x07, 0x00]),
            Bit.BufferBytes([0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x09, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x04, 0x00, 0x0B, 0x00]),
            Bit.BufferBytes([0x04, 0x00, 0x0C, 0x00, 0x04, 0x00, 0x0D, 0x00, 0x04, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x0F, 0x00]),
            Bit.BufferBytes([0x04, 0x00, 0x10, 0x00, 0x04, 0x00, 0x11, 0x00, 0x04, 0x00, 0x12, 0x00, 0x04, 0x00, 0x13, 0x00]),
            Bit.BufferBytes([0x04, 0x00, 0x14, 0x00, 0x04, 0x00, 0x15, 0x00, 0x06, 0x00, 0x01, 0x00, 0x06, 0x00, 0x02, 0x00]),
            Bit.BufferBytes([0x06, 0x00, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x09, 0x00, 0x01, 0x00]),
            Bit.BufferBytes([0x09, 0x00, 0x02, 0x00, 0x09, 0x00, 0x03, 0x00, 0x09, 0x00, 0x04, 0x00, 0x09, 0x00, 0x09, 0x00]),
            Bit.BufferBytes([0x09, 0x00, 0x0A, 0x00, 0x09, 0x00, 0x0B, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x02, 0x00]),
            Bit.BufferBytes([0x0A, 0x00, 0x03, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x0B, 0x00, 0x02, 0x00, 0x0B, 0x00, 0x03, 0x00]),
            Bit.BufferBytes([0x0B, 0x00, 0x04, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x0C, 0x00, 0x03, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x01, 0x00, 0x13, 0x00, 0x02, 0x00, 0x13, 0x00, 0x03, 0x00, 0x13, 0x00, 0x04, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x05, 0x00, 0x13, 0x00, 0x06, 0x00, 0x13, 0x00, 0x07, 0x00, 0x13, 0x00, 0x08, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x09, 0x00, 0x13, 0x00, 0x0A, 0x00, 0x13, 0x00, 0x0B, 0x00, 0x13, 0x00, 0x0C, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x0D, 0x00, 0x13, 0x00, 0x0E, 0x00, 0x13, 0x00, 0x0F, 0x00, 0x13, 0x00, 0x10, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x11, 0x00, 0x13, 0x00, 0x12, 0x00, 0x13, 0x00, 0x13, 0x00, 0x13, 0x00, 0x14, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x15, 0x00, 0x13, 0x00, 0x16, 0x00, 0x13, 0x00, 0x17, 0x00, 0x13, 0x00, 0x18, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x19, 0x00, 0x13, 0x00, 0x1A, 0x00, 0x13, 0x00, 0x1B, 0x00, 0x13, 0x00, 0x1C, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x1D, 0x00, 0x13, 0x00, 0x1E, 0x00, 0x13, 0x00, 0x1F, 0x00, 0x13, 0x00, 0x20, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x21, 0x00, 0x13, 0x00, 0x22, 0x00, 0x13, 0x00, 0x23, 0x00, 0x13, 0x00, 0x24, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x25, 0x00, 0x13, 0x00, 0x26, 0x00, 0x13, 0x00, 0x27, 0x00, 0x13, 0x00, 0x28, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x29, 0x00, 0x13, 0x00, 0x2A, 0x00, 0x13, 0x00, 0x2B, 0x00, 0x13, 0x00, 0x2C, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x2D, 0x00, 0x13, 0x00, 0x2E, 0x00, 0x13, 0x00, 0x2F, 0x00, 0x13, 0x00, 0x30, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x31, 0x00, 0x13, 0x00, 0x32, 0x00, 0x13, 0x00, 0x33, 0x00, 0x13, 0x00, 0x34, 0x00]),
            Bit.BufferBytes([0x13, 0x00, 0x35, 0x00, 0x13, 0x00, 0x36, 0x00, 0x15, 0x00, 0x01, 0x00, 0x15, 0x00, 0x02, 0x00]),
            Bit.BufferBytes([0x15, 0x00, 0x03, 0x00, 0x02, 0x00, 0x06, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x05, 0x00]),
            Bit.BufferBytes([0x09, 0x00, 0x05, 0x00, 0x09, 0x00, 0x06, 0x00, 0x09, 0x00, 0x07, 0x00, 0x09, 0x00, 0x08, 0x00]),
            Bit.BufferBytes([0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x06, 0x00, 0x04, 0x00, 0x02, 0x00]),
            Bit.BufferBytes([0x02, 0x00, 0x09, 0x00, 0x02, 0x00, 0x0B, 0x00, 0x05, 0x00, 0x00])
        );
    },
    CreateSelfInfoResponse: function (formattedScreenName) {
        return AIMPackets.CreateSNAC(0x01, 0x0f, 0, 0).concat(
            Bit.UInt8ToBytes(formattedScreenName.length),
            Bit.BufferBytes(formattedScreenName),
            Bit.BufferBytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x90, 0x00, 0x0f, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x41, 0xe9, 0xb4, 0xbb, 0x00, 0x0a, 0x00, 0x04, 0x44, 0xe3, 0xa7, 0x35, 0x00, 0x1e, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x38, 0xc4, 0x76, 0xe8])
        );
    },
    CreateFeedbagRightsResponse: function () {
        return AIMPackets.CreateSNAC(0x013, 0x03, 0, 0).concat(
            AIMPackets.CreateTLV(4,
                Bit.UInt16ToBytes(400).concat(
                    Bit.UInt16ToBytes(61),
                    Bit.UInt16ToBytes(200),
                    Bit.UInt16ToBytes(200),
                    Bit.BufferBytes([0x00, 0x01]),
                    Bit.BufferBytes([0x00, 0x01]),
                    Bit.BufferBytes([0x00, 0x32]),
                    Bit.BufferBytes([0x00, 0x00]),
                    Bit.BufferBytes([0x00, 0x00]),
                    Bit.BufferBytes([0x00, 0x03]),
                    Bit.BufferBytes([0x00, 0x00]),
                    Bit.BufferBytes([0x00, 0x00]),
                    Bit.BufferBytes([0x00, 0x00]),
                    Bit.BufferBytes([0x00, 0x80]),
                    Bit.UInt16ToBytes(400),
                    Bit.BufferBytes([0x00, 0x14]),
                    Bit.BufferBytes([0x00, 0xc8]),
                    Bit.BufferBytes([0x00, 0x01]),
                    Bit.BufferBytes([0x00, 0x00]),
                    Bit.BufferBytes([0x00, 0x01]),
                    Bit.BufferBytes([0x00, 0x00])
                )
            ),
            AIMPackets.CreateTLV(2, Bit.UInt16ToBytes(254)),
            AIMPackets.CreateTLV(3, Bit.UInt16ToBytes(508)),
            AIMPackets.CreateTLV(5, Bit.UInt16ToBytes(0)),
            AIMPackets.CreateTLV(6, Bit.UInt16ToBytes(353)),
            AIMPackets.CreateTLV(7, Bit.UInt16ToBytes(10))
        );
    },
    CreateFeedbagBuddyListResponse: function (bytes, timestamp) {
        return AIMPackets.CreateSNAC(0x13, 0x06, 0, 0).concat(
            Bit.UInt8ToBytes(0),
            Bit.UInt16ToBytes(bytes.length),
            AIMPackets.CreateBuddyList(bytes),
            Bit.UInt32ToBytes(timestamp)
        );
    },
    CreateFeedbagBuddyListNotModifiedResponse: function (date, count) {
        return AIMPackets.CreateSNAC(0x13, 0x0F, 0, 0).concat(
            Bit.UInt32ToBytes(date),
            Bit.UInt16ToBytes(count)
        );
    },
    CreateBuddyList: function (data) {
        return data.map(function (item) {
            return Bit.UInt16ToBytes(item.Name.length).concat(
                Bit.BufferBytes(item.Name),
                Bit.UInt16ToBytes(item.GroupID),
                Bit.UInt16ToBytes(item.BuddyID),
                Bit.UInt16ToBytes(item.ClassID),
                Bit.UInt16ToBytes(Bit.BufferBytes(item.Attributes).length),
                Bit.BufferBytes(item.Attributes)
            );
        }).flat(1);
    },
    CreateLocationRightsResponse: function () {
        return AIMPackets.CreateSNAC(0x02, 0x03, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x12, 0x00, 0x05, 0x00, 0x02, 0x00, 0x80, 0x00, 0x03, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x10, 0x00])
        );
    },
    CreateFeedbagBuddyRightsResponse: function () {
        return AIMPackets.CreateSNAC(0x03, 0x03, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x02, 0x00, 0x02, 0x07, 0xd0, 0x00, 0x01, 0x00, 0x02, 0x00, 0xdC, 0x00, 0x04, 0x00, 0x02, 0x00, 0x20])
        );
    },
    CreateIcbmParamsResponse: function () {
        return AIMPackets.CreateSNAC(0x04, 0x05, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x03, 0x84, 0x03, 0xe7, 0x00, 0x00, 0x03, 0xe8])
        );
    },
    CreateBosRightsResponse: function () {
        return AIMPackets.CreateSNAC(0x09, 0x03, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x02, 0x00, 0x02, 0x00, 0xdc, 0x00, 0x01, 0x00, 0x02, 0x00, 0xdc])
        );
    },
    CreateBuddyArrived: function (formattedScreenName, signOnTimestamp, capabilities) {
        return AIMPackets.CreateSNAC(0x03, 0x0b, 0, 0).concat(
            Bit.UInt8ToBytes(formattedScreenName.length),
            Bit.BufferBytes(formattedScreenName),
            Bit.UInt16ToBytes(0),
            Bit.UInt16ToBytes(4),
            AIMPackets.CreateTLV(0x01, [0x20]),
            AIMPackets.CreateTLV(0x03, Bit.UInt32ToBytes(signOnTimestamp)),
            AIMPackets.CreateTLV(0x0d, capabilities),
            AIMPackets.CreateTLV(0x0f, Bit.UInt32ToBytes(Math.floor(new Date().getTime() / 1000) - signOnTimestamp)),
        );
    },
    CreateBuddyDeparted: function (formattedScreenName) {
        return AIMPackets.CreateSNAC(0x03, 0x0c, 0, 0).concat(
            Bit.UInt8ToBytes(formattedScreenName.length),
            Bit.BufferBytes(formattedScreenName),
            Bit.BufferBytes([0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00])
        );
    },
    CreateLocateDirectoryInfoResponse: function () {
        return AIMPackets.CreateSNAC(0x02, 0x0c, 0, 0).concat(
            Bit.BufferBytes([0x00, 0x01, 0x00, 0x00])
        );
    },
    CreateServiceResponse: function (host, port, group, cookie) {
        return AIMPackets.CreateSNAC(0x01, 0x05, 0, 0).concat(
            AIMPackets.CreateTLV(0x0d, Bit.UInt16ToBytes(group)),
            AIMPackets.CreateTLV(0x05, Bit.BufferBytes([host, port].join(':'))),
            AIMPackets.CreateTLV(0x06, Bit.BufferBytes(cookie))
        );
    },
    GetFLAP: function (bytes) {
        return {
            channel: Bit.BytesToUInt8(bytes.slice(1, 2)),
            sequence: Bit.BytesToUInt16(bytes.slice(2, 4)),
            size: Bit.BytesToUInt16(bytes.slice(4, 6))
        };
    },
    GetSNAC: function (bytes) {
        let SNAC = bytes.slice(0, 10);
        let foodGroup = Strings.DecimalToHex(Bit.BytesToUInt16(SNAC.slice(0, 2)));
        let type = Strings.DecimalToHex(Bit.BytesToUInt16(SNAC.slice(2, 4)));
        let flags = Bit.BytesToUInt16(SNAC.slice(4, 6));
        let requestId = Bit.BytesToUInt32(SNAC.slice(6, 10));
        var payload = bytes.slice(10);
        var out = {
            foodGroup: foodGroup,
            type: type,
            flags: flags,
            requestId
        };
        if (payload.length > 0) {
            if (foodGroup === 13 && type === 5) {
                out.date = Bit.BytesToUInt32(payload.slice(0, 4));
                out.count = Bit.BytesToUInt16(payload.slice(4, 6));
            } else if (foodGroup === 1 && type === 17) {
                out.families = AIMPackets.GetServicesFamilies(payload);
            } else if (foodGroup === 1 && type === 8) {
                out.rateLimits = AIMPackets.GetRateLimitsTLVs(payload)
            } else if (foodGroup === 2 && type === '0b') {
                out.screenName = Buffer.from(payload.slice(1, Bit.BytesToUInt8(payload.slice(0, 1)) + 1)).toString('ascii');
            } else if (foodGroup === 1 && type === 4) {
                out.groupId = Bit.BytesToUInt16(payload.slice(0, 4));
            } else if (foodGroup === 13 && type == 08) {
                out.payload = payload;
                out.items = AIMPackets.GetSSIItems(payload);
            } else {
                out.tlvs = AIMPackets.GetTLVs(payload);
            }
        }
        return out;
    },
    GetRateLimitsTLVs: function (bytes) {
        var _buffer = bytes;
        var out = [];
        while (_buffer.length >= 4) {
            out.push(Bit.BytesToUInt16(_buffer.splice(0, 2)));
        }
        return out;
    },
    GetSSIItems: function (bytes) {
        var _buffer = [...bytes];
        var out = [];
        while (_buffer.length > 0) {
            let length = Bit.BytesToUInt16(_buffer.splice(0, 2));
            let name = Bit.BytesBuffer(_buffer.splice(0, length)).toString('ascii');
            let groupId = Bit.BytesToUInt16(_buffer.splice(0, 2));
            let itemId = Bit.BytesToUInt16(_buffer.splice(0, 2));
            let classId = Bit.BytesToUInt16(_buffer.splice(0, 2));
            let tlvlength = Bit.BytesToUInt16(_buffer.splice(0, 2));
            let attributes = _buffer.slice(0, tlvlength);
            let tlvs = AIMPackets.GetTLVs(_buffer.splice(0, tlvlength));
            out.push({
                length: length,
                name: name,
                groupId: groupId,
                itemId: itemId,
                classId: classId,
                attributes: attributes,
                tlvs: tlvs
            });
        }
        return out;
    },
    GetServicesFamilies: function (bytes) {
        var _buffer = bytes;
        var out = {};
        while (_buffer.length >= 4) {
            var type = Strings.DecimalToHexString(Bit.BytesToUInt16(_buffer.splice(0, 2)), true);
            var version = Bit.BytesToUInt16(_buffer.splice(0, 2));
            out[type] = version
        }
        return out;
    },
    GetTLVs: function (bytes) {
        var _buffer = bytes;
        var out = {};
        while (_buffer.length >= 4) {
            var type = Strings.DecimalToHexString(Bit.BytesToUInt16(_buffer.splice(0, 2)), true);
            var length = Bit.BytesToUInt16(_buffer.splice(0, 2));
            var data = AIMPackets.FormatTLV(type, _buffer.splice(0, length));
            out[type] = { length: length, data: data };
        }
        return out;
    },
    CreateTLV: function (type, bytes) {
        return Bit.UInt16ToBytes(type).concat(Bit.UInt16ToBytes(bytes.length), bytes);
    },
    FormatTLV: function (type, bytes) {
        if (bytes.length < 1) { return null; }
        switch (type) {
            case '0x01':
            case '0x02':
            case '0x03':
            case '0x04':
            case '0x0b':
            case '0x0e':
            case '0x0f':
            case '0x11':
            case '0x41':
            case '0x42':
            case '0x45':
            case '0x46':
            case '0x47':
            case '0x48':
            case '0x49':
            case '0x54':
                return Bit.BytesBuffer(bytes).toString('ascii');
            case '0x06':
                return Strings.BytesToHexString(bytes, true);
            case '0x0c':
            case '0x0d':
            case '0x08':
            case '0x09':
            case '0x16':
            case '0x17':
            case '0x18':
            case '0x1a':
            case '0x19':
                return Bit.BytesToUInt16(bytes);
            case '0x40':
            case '0x44':
            case '0x14':
                return Bit.BytesToUInt32(bytes);
            case '0x05':
            case '0x25':
                return Bit.BytesBuffer(bytes).toJSON().data;
            default:
                return null;
        }
    }
};
var Bit = {
    BufferBytes: function (data) {
        return Buffer.from(data).toJSON().data;
    },
    BytesBuffer: function (data) {
        return Buffer.from(data);
    },
    BytesToUInt8: function (bytes) {
        return Buffer.from(bytes).readUInt8();
    },
    BytesToUInt16: function (bytes) {
        return Buffer.from(bytes).readUInt16BE();
    },
    BytesToUInt32: function (bytes) {
        return Buffer.from(bytes).readUInt32BE();
    },
    UInt8ToBytes: function (num) {
        var b = Buffer.alloc(1);
        b.writeUInt8(num);
        return b.toJSON().data;
    },
    UInt16ToBytes: function (num) {
        var b = Buffer.alloc(2);
        b.writeUInt16BE(num)
        return b.toJSON().data;
    },
    UInt32ToBytes: function (num) {
        var b = Buffer.alloc(4);
        b.writeUInt32BE(num)
        return b.toJSON().data;
    }
};
var Constants = {
    _FLAP_VERSION: [0, 0, 0, 1],
    _AIM_MD5_STRING: 'AOL Instant Messenger (SM)'
};
var Crypto = {
    MD5: function (string) {
        var hasher = crypto.createHash('md5');
        hasher.update(string);
        return hasher.digest();
    }
};
var Strings = {
    DecimalToHexString: function (code, prefix) {
        return [prefix ? '0x' : '', ['00', code.toString(16)].join('').slice(-2)].join('');
    },
    DecimalToHex: function (num) {
        return !isNaN(parseInt(num.toString(16))) ? parseInt(num.toString(16)) : ['00', num.toString(16)].join('').slice(-2);
    },
    HexToDecimal: function (code) {
        return parseInt(code, 16);
    },
    BytesToHexString: function (bytes) {
        return bytes.map(function (item) { return Strings.DecimalToHex(item); }).join('');
    },
    GenerateInt: function (lowerLimit, upperLimit) {
        return Math.floor((((upperLimit - lowerLimit) + 1) * Math.random()) + lowerLimit);
    },
    GenerateTicket: function () {
        var out = [];
        for (i = 0; i < 10; i++) {
            out.push(String.fromCharCode(Strings.GenerateInt(48, 57)));
        }
        return out.join('');
    },
    GenerateCookie: function () {
        var out = [];
        for (i = 0; i < 256; i++) {
            out.push(String.fromCharCode(Strings.GenerateInt(0, 255)));
        }
        return Crypto.MD5(out.join(''));
    },
    CheckPassword: function (ticket, password, hash) {
        var knownbytes = Bit.BufferBytes(Crypto.MD5(Bit.BytesBuffer(Bit.BufferBytes(Buffer.from(ticket)).concat(Bit.BufferBytes(Crypto.MD5(password)), Bit.BufferBytes(Constants._AIM_MD5_STRING)))));
        var knownstring = Strings.BytesToHexString(knownbytes);
        var checkstring = Strings.BytesToHexString(hash);
        return knownstring === checkstring;
    }
};

module.exports = {
    AIMPackets: AIMPackets,
    Constants: Constants,
    Crypto: Crypto,
    Bit: Bit,
    Strings: Strings
}