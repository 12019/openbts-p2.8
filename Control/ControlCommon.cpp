/**@file Common-use functions for the control layer. */

/*
* Copyright 2008, 2010 Free Software Foundation, Inc.
*
* This software is distributed under the terms of the GNU Affero Public License.
* See the COPYING file in the main directory for details.
*
* This use of this software may be subject to additional restrictions.
* See the LEGAL file in the main directory for details.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include "ControlCommon.h"
#include "TransactionTable.h"
extern "C" {
#include <osmocom/gsm/comp128.h>
}
#include <GSMLogicalChannel.h>
#include <GSML3Message.h>
#include <GSML3CCMessages.h>
#include <GSML3RRMessages.h>
#include <GSML3MMMessages.h>
#include <GSMConfig.h>
#include <SIPInterface.h>
#include <SIPUtility.h>
#include <SIPMessage.h>
#include <SIPEngine.h>
#include <SubscriberRegistry.h>
#include <Logger.h>
#undef WARNING

using namespace std;
using namespace SIP;
using namespace GSM;
using namespace Control;

// FIXME -- getMessage should return an L3Frame, not an L3Message.
// This will mean moving all of the parsing into the control layer.
// FIXME -- This needs an adjustable timeout.

L3Message* Control::getMessage(LogicalChannel *LCH, unsigned SAPI)
{
	unsigned timeout_ms = LCH->N200() * T200ms;
	L3Frame *rcv = LCH->recv(timeout_ms,SAPI);
	if (rcv==NULL) {
		LOG(NOTICE) << "timeout";
		throw ChannelReadTimeout();
	}
	LOG(DEBUG) << "received " << *rcv;
	Primitive primitive = rcv->primitive();
	if (primitive!=DATA) {
		LOG(NOTICE) << "unexpected primitive " << primitive;
		delete rcv;
		throw UnexpectedPrimitive();
	}
	L3Message *msg = parseL3(*rcv);
	delete rcv;
	if (msg==NULL) {
		LOG(NOTICE) << "unparsed message";
		throw UnsupportedMessage();
	}
	return msg;
}

// Try to authenticate mobID using given channel
unsigned Control::attemptAuth(GSM::L3MobileIdentity mobID, GSM::LogicalChannel* LCH)
{
    const char *IMSI = mobID.digits();
    string name = "IMSI" + string(IMSI);

// Try to register the IMSI.
// This will be set true if registration succeeded in the SIP world.
    bool success = false;
    string RAND;
    try {
	SIPEngine engine(gConfig.getStr("SIP.Proxy.Registration").c_str(),IMSI);
	LOG(DEBUG) << "waiting for registration of " << IMSI << " on " << gConfig.getStr("SIP.Proxy.Registration");
	success = engine.Register(SIPEngine::SIPRegister, &RAND); 
    }
    catch(SIPTimeout) {
	LOG(ALERT) "SIP registration timed out.  Is the proxy running at " << gConfig.getStr("SIP.Proxy.Registration");
	if(gConfig.defines("SIP.Proxy.Registration.Fallback"))
	{// Fallback procedure to obtain RAND
	    RAND = GSM::L3RAND().getRAND(16);
	    LOG(INFO) << "Fallback RAND procedure initiated." << endl;
	}
	else
	{// Reject with a "network failure" cause code, 0x11.
	    LCH->send(L3LocationUpdatingReject(0x11));
	    // HACK -- wait long enough for a response
	    // FIXME -- Why are we doing this?
	    sleep(4);
	    // Release the channel and return.
	    LCH->send(L3ChannelRelease());
	    return 1;
	}
    }

    // Did we get a RAND for challenge-response?
    if (RAND.length() != 0) {
	// Cache RAND value
	gTMSITable.setRAND(IMSI, RAND.c_str());
	LOG(DEBUG) << "RAND " << RAND.c_str() << " set for IMSI " << IMSI;
	// Get the mobile's SRES.
	LOG(INFO) << "sending " << RAND << " to mobile";
	uint64_t uRAND;
	uint64_t lRAND;
	gSubscriberRegistry.stringToUint(RAND, &uRAND, &lRAND);
	LCH->send(L3AuthenticationRequest(0,L3RAND(uRAND,lRAND)));
	L3Message* msg = getMessage(LCH);
	L3AuthenticationResponse *resp = dynamic_cast<L3AuthenticationResponse*>(msg);
	if (!resp) {
		if (msg) {
			LOG(WARNING) << "Unexpected message " << *msg;
			delete msg;
		}
		// FIXME -- We should differentiate between wrong message and no message at all.
		throw UnexpectedMessage();
	}
	LOG(INFO) << *resp;
	uint32_t mobileSRES = resp->SRES().value();
	delete msg;
	// verify SRES 
	ostringstream os;
	os << hex << mobileSRES;
	string SRESstr = os.str();
	try {
    	    SIPEngine engine(gConfig.getStr("SIP.Proxy.Registration").c_str(),IMSI);
	    LOG(DEBUG) << "waiting for authentication of " << IMSI << " on " << gConfig.getStr("SIP.Proxy.Registration");
	    success = engine.Register(SIPEngine::SIPRegister, &RAND, IMSI, SRESstr.c_str()); 
	    if (!success) {
		LCH->send(L3AuthenticationReject());
		LCH->send(L3ChannelRelease());
		return 2;
	    }
	}
	catch(SIPTimeout) {
	    LOG(ALERT) "SIP authentication timed out.  Is the proxy running at " << gConfig.getStr("SIP.Proxy.Registration");
	    if(!gConfig.defines("SIP.Proxy.Registration.Fallback"))
	    {// Reject with a "network failure" cause code, 0x11.
		LCH->send(L3LocationUpdatingReject(0x11));
		// HACK -- wait long enough for a response
		// FIXME -- Why are we doing this?
		sleep(4);
		// Release the channel and return.
		LCH->send(L3ChannelRelease());
		return 1;
	    } 
	    else 
	    {// Fallback to local SRES check
		uint64_t Kc;
		uint8_t SRES[4];
		comp128((uint8_t *)gTMSITable.getKi(IMSI), (uint8_t *)RAND.c_str(), SRES, (uint8_t *)&Kc);
		mobID.setKC(Kc);
		int chk = SRESstr.compare(0, 4, (char *) SRES, 4);
		LOG(INFO) << "mobile's SRES=0x" << hex << mobileSRES << "SRES=0x" << hex << SRES << " Kc=0x" << hex << Kc;
		if(0 != chk) {
			LOG(INFO) << "Local SRES authentication failed." << endl;
			LCH->send(L3AuthenticationReject());
			LCH->send(L3ChannelRelease());
		}
		else {
			LOG(INFO) << "Local SRES authentication OK." << endl;
			success = true;
		}
	    }
	}
	if(success) {// Ciphering Mode Procedures, GSM 04.08 3.4.7.
	    LOG(INFO) << "Ciphering Command Will Send";
	    LCH->send(GSM::L3CipheringModeCommand());
	    LOG(INFO) << "Ciphering Command Sent";
	    L3Frame* resp = LCH->recv();
	    LOG(INFO) << "Received";
	    if(!resp) { LOG(NOTICE) << "Ciphering Error"; } 
	    else { LOG(INFO) << *resp <<"Responce"; }
	    delete resp;
	    LOG(INFO) << "Ciphering Completed";
	    return 0;
	}
    }
    return 3;
}

/* Resolve a mobile ID to an IMSI and return TMSI if it is assigned. */
unsigned  Control::resolveIMSI(bool sameLAI, L3MobileIdentity& mobileID, LogicalChannel* LCH)
{
	// Returns known or assigned TMSI.
	assert(LCH);
	LOG(DEBUG) << "resolving mobile ID " << mobileID << ", sameLAI: " << sameLAI;

	// IMSI already?  See if there's a TMSI already, too.
	if (mobileID.type()==IMSIType) return gTMSITable.TMSI(mobileID.digits());

	// IMEI?  WTF?!
	// FIXME -- Should send MM Reject, cause 0x60, "invalid mandatory information".
	if (mobileID.type()==IMEIType) throw UnexpectedMessage();

	// Must be a TMSI.
	// Look in the table to see if it's one we assigned.
	unsigned TMSI = mobileID.TMSI();
	char* IMSI = NULL;
	if (sameLAI) IMSI = gTMSITable.IMSI(TMSI);
	if (IMSI) {
		// We assigned this TMSI already; the TMSI/IMSI pair is already in the table.
		mobileID = L3MobileIdentity(IMSI);
		LOG(DEBUG) << "resolving mobile ID (table): " << mobileID;
		free(IMSI);
		return TMSI;
	}
	// Not our TMSI.
	// Phones are not supposed to do this, but many will.
	// If the IMSI's not in the table, ASK for it.
	LCH->send(L3IdentityRequest(IMSIType));
	// FIXME -- This request times out on T3260, 12 sec.  See GSM 04.08 Table 11.2.
	L3Message* msg = getMessage(LCH);
	L3IdentityResponse *resp = dynamic_cast<L3IdentityResponse*>(msg);
	if (!resp) {
		if (msg) delete msg;
		throw UnexpectedMessage();
	}
	mobileID = resp->mobileID();
	LOG(INFO) << resp;
	delete msg;
	LOG(DEBUG) << "resolving mobile ID (requested): " << mobileID;
	// FIXME -- Should send MM Reject, cause 0x60, "invalid mandatory information".
	if (mobileID.type()!=IMSIType) throw UnexpectedMessage();
	// Return 0 to indicate that we have not yet assigned our own TMSI for this phone.
	return 0;
}

/* Resolve a mobile ID to an IMSI and return KI if it is assigned. */
unsigned char*  Control::resolveKI(L3MobileIdentity& mobID, LogicalChannel* LCH)
{
	// Returns known or assigned TMSI.
	assert(LCH);
	LOG(DEBUG) << "resolving mobile ID " << mobID ;

	// IMSI already?  See if there's a TMSI already, too.
	// This is a linear time operation, but should only happen on
	// the first registration by this mobile.
	if (mobID.type() == IMSIType) return (unsigned char *)gTMSITable.getKi(mobID.digits());
	return NULL;
}

/* Resolve a mobile ID to an IMSI. */
void  Control::resolveIMSI(L3MobileIdentity& mobileIdentity, LogicalChannel* LCH)
{
	// Are we done already?
	if (mobileIdentity.type()==IMSIType) return;

	// If we got a TMSI, find the IMSI.
	if (mobileIdentity.type()==TMSIType) {
		char *IMSI = gTMSITable.IMSI(mobileIdentity.TMSI());
		if (IMSI) mobileIdentity = L3MobileIdentity(IMSI);
		free(IMSI);
	}

	// Still no IMSI?  Ask for one.
	if (mobileIdentity.type()!=IMSIType) {
		LOG(NOTICE) << "MOC with no IMSI or valid TMSI.  Reqesting IMSI.";
		LCH->send(L3IdentityRequest(IMSIType));
		// FIXME -- This request times out on T3260, 12 sec.  See GSM 04.08 Table 11.2.
		L3Message* msg = getMessage(LCH);
		L3IdentityResponse *resp = dynamic_cast<L3IdentityResponse*>(msg);
		if (!resp) {
			if (msg) delete msg;
			throw UnexpectedMessage();
		}
		mobileIdentity = resp->mobileID();
		delete msg;
	}

	// Still no IMSI??
	if (mobileIdentity.type()!=IMSIType) {
		// FIXME -- This is quick-and-dirty, not following GSM 04.08 5.
		LOG(WARNING) << "MOC setup with no IMSI";
		// Cause 0x60 "Invalid mandatory information"
		LCH->send(L3CMServiceReject(L3RejectCause(0x60)));
		LCH->send(L3ChannelRelease());
		// The SIP side and transaction record don't exist yet.
		// So we're done.
		return;
	}
}





// vim: ts=4 sw=4
