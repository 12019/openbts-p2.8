/**@file GSM/SIP Mobility Management, GSM 04.08. */
/*
* Copyright 2008, 2009, 2010, 2011 Free Software Foundation, Inc.
* Copyright 2011 Range Networks, Inc.
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


#include <Timeval.h>

#include "ControlCommon.h"
#include "MobilityManagement.h"
#include "SMSControl.h"
#include "CallControl.h"
#include "RRLPServer.h"
extern "C" {
#include <osmocom/gsm/comp128.h>
}
#include <GSMLogicalChannel.h>
#include <GSML3RRMessages.h>
#include <GSML3MMMessages.h>
#include <GSML3CCMessages.h>
#include <GSMConfig.h>

using namespace std;

#include <SIPInterface.h>
#include <SIPUtility.h>
#include <SIPMessage.h>
#include <SIPEngine.h>
#include <SubscriberRegistry.h>

using namespace SIP;

#include <Regexp.h>
#include <Logger.h>
#undef WARNING


using namespace GSM;
using namespace Control;


/** Controller for CM Service requests, dispatches out to multiple possible transaction controllers. */
void Control::CMServiceResponder(const L3CMServiceRequest* cmsrq, LogicalChannel* DCCH)
{
	assert(cmsrq);
	assert(DCCH);
	LOG(INFO) << *cmsrq;
	switch (cmsrq->serviceType().type()) {
		case L3CMServiceType::MobileOriginatedCall:
			MOCStarter(cmsrq,DCCH);
			break;
		case L3CMServiceType::ShortMessage:
			MOSMSController(cmsrq,DCCH);
			break;
		default:
			LOG(NOTICE) << "service not supported for " << *cmsrq;
			// Cause 0x20 means "serivce not supported".
			DCCH->send(L3CMServiceReject(0x20));
			DCCH->send(L3ChannelRelease());
	}
	// The transaction may or may not be cleared,
	// depending on the assignment type.
}




/** Controller for the IMSI Detach transaction, GSM 04.08 4.3.4. */
void Control::IMSIDetachController(const L3IMSIDetachIndication* idi, LogicalChannel* DCCH)
{
	assert(idi);
	assert(DCCH);
	LOG(INFO) << *idi;

	// The IMSI detach maps to a SIP unregister with the local Asterisk server.
	if (gConfig.getNum("GSM.Authentication") < 2) { // check if SIP register/auth were used at all
	    try { // FIXME -- Resolve TMSIs to IMSIs.
		if (idi->mobileID().type()==IMSIType) {
		    SIPEngine engine(gConfig.getStr("SIP.Proxy.Registration").c_str(), idi->mobileID().digits());
		    AuthenticationParameters authParams(idi->mobileID());
		    engine.unregister(authParams);
		}
	    }
	    catch(SIPTimeout) {
		LOG(ALERT) "SIP registration timed out.  Is Asterisk running?";
	    }
	}
	// No reponse required, so just close the channel.
	DCCH->send(L3ChannelRelease());
	// Many handsets never complete the transaction.
	// So force a shutdown of the channel.
	DCCH->send(HARDRELEASE);
}




/**
	Send a given welcome message from a given short code.
	@return true if it was sent
*/
bool sendWelcomeMessage(const char* messageName, const char* shortCodeName, const char *IMSI, LogicalChannel* DCCH, const char *whiteListCode = NULL)
{
	if (!gConfig.defines(messageName)) return false;
	LOG(INFO) << "sending " << messageName << " message to handset";
	ostringstream message;
	message << gConfig.getStr(messageName) << " IMSI:" << IMSI;
	if (whiteListCode) {
		message << ", white-list code: " << whiteListCode;
	}
	// This returns when delivery is acked in L3.
	deliverSMSToMS(
		gConfig.getStr(shortCodeName).c_str(),
		message.str().c_str(), "text/plain",
		random()%7,DCCH);
	return true;
}

/**
	Controller for the Location Updating transaction, GSM 04.08 4.4.4.
	@param lur The location updating request.
	@param DCCH The Dm channel to the MS, which will be released by the function.
*/
void Control::LocationUpdatingController(const L3LocationUpdatingRequest* lur, LogicalChannel* DCCH)
{
	assert(DCCH);
	assert(lur);
	LOG(INFO) << *lur;

	// The location updating request gets mapped to a SIP
	// registration with the Asterisk server.

	// We also allocate a new TMSI for every handset we encounter.
	// If the handset is allow to register it may receive a TMSI reassignment.

	// Resolve an IMSI and see if there's a pre-existing IMSI-TMSI mapping.
	// This operation will throw an exception, caught in a higher scope,
	// if it fails in the GSM domain.
	L3MobileIdentity mobileID = lur->mobileID();
	bool sameLAI = (lur->LAI() == gBTS.LAI());
	unsigned preexistingTMSI = resolveIMSI(sameLAI,mobileID,DCCH);
	const char *IMSI = mobileID.digits();
	// IMSIAttach set to true if this is a new registration.
	bool IMSIAttach = (preexistingTMSI==0);

	// We assign generate a TMSI for every new phone we see,
	// even if we don't actually assign it.
	unsigned newTMSI = 0;
	if (!preexistingTMSI) newTMSI = gTMSITable.assign(IMSI,lur);

	string name = "IMSI" + string(IMSI);

	// Try to register the IMSI.
	// This will be set true if registration succeeded in the SIP world.

	bool success = auth_reg(mobileID, DCCH);

	// This allows us to configure Open Registration
	bool openRegistration = false;
	if (gConfig.defines("Control.LUR.OpenRegistration")) {
		if (!gConfig.defines("Control.LUR.OpenRegistration.Message")) {
			gConfig.set("Control.LUR.OpenRegistration.Message","Welcome to the test network.  Your IMSI is ");
		}
		Regexp rxp(gConfig.getStr("Control.LUR.OpenRegistration").c_str());
		openRegistration = rxp.match(IMSI);
		if (gConfig.defines("Control.LUR.OpenRegistration.Reject")) {
			Regexp rxpReject(gConfig.getStr("Control.LUR.OpenRegistration.Reject").c_str());
			bool openRegistrationReject = rxpReject.match(IMSI);
			openRegistration = openRegistration && !openRegistrationReject;
		}
	}

	// Query for IMEI?
	if (gConfig.defines("Control.LUR.QueryIMEI")) {
		DCCH->send(L3IdentityRequest(IMEIType));
		L3Message* msg = getMessage(DCCH);
		L3IdentityResponse *resp = dynamic_cast<L3IdentityResponse*>(msg);
		if (!resp) {
			if (msg) {
				LOG(WARNING) << "Unexpected message " << *msg;
				delete msg;
			}
			throw UnexpectedMessage();
		}
		LOG(INFO) << *resp;
		string new_imei = resp->mobileID().digits();
		if (!gTMSITable.IMEI(IMSI,new_imei.c_str())){
			LOG(WARNING) << "failed access to TMSITable";
		} 

		//query subscriber registry for old imei, update if neccessary
		string old_imei = gSubscriberRegistry.imsiGet(name, "hardware");
		
		//if we have a new imei and either there's no old one, or it is different...
		if (!new_imei.empty() && (old_imei.empty() || old_imei != new_imei)){
			LOG(INFO) << "Updating IMSI" << IMSI << " to IMEI:" << new_imei;
			if (gSubscriberRegistry.imsiSet(name,"RRLPSupported", "1")) {
			 	LOG(INFO) << "SR RRLPSupported update problem";
			}
			if (gSubscriberRegistry.imsiSet(name,"hardware", new_imei)) {
				LOG(INFO) << "SR hardware update problem";
			}
		}
		delete msg;
	}

	if (IMSIAttach && gConfig.defines("Control.LUR.QueryClassmarkIgnoreTMSI")) IMSIAttach = 1;
	// Query for classmark?
	if (IMSIAttach && gConfig.defines("Control.LUR.QueryClassmark")) {
		DCCH->send(L3ClassmarkEnquiry());
		L3Message* msg = getMessage(DCCH);
		L3ClassmarkChange *resp = dynamic_cast<L3ClassmarkChange*>(msg);
		if (!resp) {
			if (msg) {
				LOG(WARNING) << "Unexpected message " << *msg;
				delete msg;
			}
			throw UnexpectedMessage();
		}
		LOG(INFO) << *resp;
		const L3MobileStationClassmark2& classmark = resp->classmark();
		if (!gTMSITable.classmark(IMSI,classmark))
			LOG(WARNING) << "failed access to TMSITable";
		delete msg;
	}

	// We fail closed unless we're configured otherwise
	if (!success && !openRegistration) {
		LOG(INFO) << "registration FAILED: " << mobileID;
		DCCH->send(L3LocationUpdatingReject(gConfig.getNum("Control.LUR.UnprovisionedRejectCause")));
		if (!preexistingTMSI) {
			sendWelcomeMessage( "Control.LUR.FailedRegistration.Message",
				"Control.LUR.FailedRegistration.ShortCode", IMSI,DCCH);
		}
		// Release the channel and return.
		DCCH->send(L3ChannelRelease());
		return;
	}

	// If success is true, we had a normal registration.
	// Otherwise, we are here because of open registration.
	// Either way, we're going to register a phone if we arrive here.

	LOG(INFO) << "registering " << mobileID << " auth: " << success << " openRegistration: " << openRegistration;


	// Send the "short name" and time-of-day.
	if (IMSIAttach && gConfig.defines("GSM.Identity.ShortName")) {
		DCCH->send(L3MMInformation(gConfig.getStr("GSM.Identity.ShortName").c_str()));
	}
	// Accept. Make a TMSI assignment, too, if needed.
	if (preexistingTMSI || !gConfig.defines("Control.LUR.SendTMSIs")) {
		DCCH->send(L3LocationUpdatingAccept(gBTS.LAI()));
	} else {
		assert(newTMSI);
		DCCH->send(L3LocationUpdatingAccept(gBTS.LAI(),newTMSI));
		// Wait for MM TMSI REALLOCATION COMPLETE (0x055b).
		L3Frame* resp = DCCH->recv(1000);
		// FIXME -- Actually check the response type.
		if (!resp) {
			LOG(NOTICE) << "no response to TMSI assignment";
		} else {
			LOG(INFO) << *resp;
		}
		delete resp;
	}

	if (gConfig.defines("Control.LUR.QueryRRLP")) {
		// Query for RRLP
		if (!sendRRLP(mobileID, DCCH)) {
			LOG(INFO) << "RRLP request failed";
		}
	}

	// If this is an IMSI attach, send a welcome message.
	if (IMSIAttach) {
		if (success) {
			sendWelcomeMessage( "Control.LUR.NormalRegistration.Message",
				"Control.LUR.NormalRegistration.ShortCode", IMSI, DCCH);
		} else {
			sendWelcomeMessage( "Control.LUR.OpenRegistration.Message",
				"Control.LUR.OpenRegistration.ShortCode", IMSI, DCCH);
		}
	}

	// Release the channel and return.
	DCCH->send(L3ChannelRelease());
	return;
}

bool registerIMSI(Control::AuthenticationParameters& authParams, GSM::LogicalChannel* LCH)
{
	// Try to register the IMSI.
	// This will be set true if registration succeeded in the SIP world.
	try {
		SIPEngine engine(gConfig.getStr("SIP.Proxy.Registration").c_str(),authParams.mobileID().digits());
		LOG(DEBUG) << "waiting for registration of " << authParams.mobileID() << " on " << gConfig.getStr("SIP.Proxy.Registration");
		return engine.Register(SIPEngine::SIPRegister, authParams);
	}
	catch(SIPTimeout) {
		LOG(ALERT) << "SIP registration timed out.  Is the proxy running at " << gConfig.getStr("SIP.Proxy.Registration");
		// Reject with a "network failure" cause code, 0x11.
		LCH->send(L3LocationUpdatingReject(0x11));
//		gReports.incr("OpenBTS.GSM.MM.LUR.Timeout");
		// HACK -- wait long enough for a response
		// FIXME -- Why are we doing this?
		sleep(4);
		// Release the channel and return.
		LCH->send(L3ChannelRelease());
		return false;
	}
}

inline void cipher(AuthenticationParameters& authParams, GSM::LogicalChannel* LCH) { // cipher mode commands
    if (authParams.isKCset() && gConfig.getNum("GSM.Encryption")) {
	LCH->setKc(authParams.get_Kc());
	LOG(DEBUG) << "Ciphering key set for LCH , KC = " << authParams.get_Kc();
	LCH->send(GSM::L3CipheringModeCommand(authParams.get_a5()));
	LCH->activateDecryption(authParams.get_a5());
	LOG(DEBUG) << "Decryption activated: " << authParams.get_a5() << "Ciphering Mode Command sent over " << LCH->type();
	L3Message* mc_msg = getMessage(LCH);
	L3CipheringModeComplete* mode_compl = dynamic_cast<L3CipheringModeComplete*>(mc_msg);
	if(!mode_compl) {
	    if (mc_msg) {
		LOG(DEBUG) << "Waiting for L3CipheringModeComplete, got Unexpected message " << *mc_msg;
		delete mc_msg;
	    }
	    // FIXME -- We should differentiate between wrong message and no message at all.
	    throw UnexpectedMessage();
	} else {
	    LOG(DEBUG) << *mode_compl << "Responce received, activating encryption.";
	    LCH->activateEncryption(authParams.get_a5());
	    delete mc_msg;
	}
    }
}

inline uint32_t auth_re(AuthenticationParameters& authParams, GSM::LogicalChannel* LCH) { // authentication request-responce
    if (authParams.isRANDset()) { // Did we get a RAND for challenge-response?
	L3AuthenticationRequest req = (UMTS == authParams.get_alg()) ? L3AuthenticationRequest(authParams.CKSN(), authParams.RAND(), authParams.AUTN()) : L3AuthenticationRequest(authParams.CKSN(), authParams.RAND());
	if (UMTS == authParams.get_alg()) {
	    LOG(DEBUG) << "AUTN: " << authParams.AUTN() << " is set: " << authParams.isAUTNset();
	} else {
	    LOG(DEBUG) << "ALG: " << Control::print_a3a8(authParams.get_alg());
	}
	LCH->send(req); // Request the mobile's SRES.
	LOG(DEBUG) << "SENT L3AuthenticationRequest " << req;
	L3Message* msg = getMessage(LCH);
	L3AuthenticationResponse* resp = dynamic_cast<L3AuthenticationResponse*>(msg);
	if (!resp) {
	    if (msg) {
		LOG(DEBUG) << "Waiting for L3AuthenticationResponse, got Unexpected message " << *msg;
		delete msg;
	    }
	    throw UnexpectedMessage(); // FIXME -- We should differentiate between wrong message and no message at all.
	}
	return resp->SRES().value();
	LOG(DEBUG) << "Recieved L3AuthenticationResponse " << *resp;
    } else LOG(ERR) << "RAND is not set!";
    return 0;
}

bool Control::auth_sip(AuthenticationParameters& authParams, GSM::LogicalChannel* LCH) {
    bool success = false;
    authParams.set_SRES(auth_re(authParams, LCH));

    if (registerIMSI(authParams, LCH)) { // verify SRES
	LOG(DEBUG) << "SIP authentication success for" << authParams.mobileID();
	success = true;
	cipher(authParams, LCH);
    } else {
	LOG(DEBUG) << "Failed to verify SRES";
    }
    return success;
}

bool auth_local(AuthenticationParameters& authParams, GSM::LogicalChannel* LCH) {
    string IMSI = string("IMSI") + string(authParams.get_mobileID()), RAND = gSubscriberRegistry.imsiGet(IMSI, "rand"), a3a8 = gSubscriberRegistry.imsiGet(IMSI, "a3_a8");
    if (0 == RAND.length()) {
	LOG(DEBUG) << "Failed to obtain RAND for " << authParams.mobileID();
	return false;
    }

    if (a3a8 == "UMTS") { // add AUTN if we act as radio frontend for UMTS core
	authParams.set_alg(UMTS);
	string AUTN = gSubscriberRegistry.imsiGet(IMSI, "opc");
	authParams.set_AUTN(AUTN);
	LOG(DEBUG) << "Loaded " << AUTN.length() << " bytes AUTN: " << AUTN << " set " << authParams.isAUTNset();
    }
    authParams.set_RAND(RAND);
    authParams.set_SRES(auth_re(authParams, LCH));

    if (a3a8 == "UMTS") { // MITM - no need to actually check SRES, just pretend it's OK
	LOG(DEBUG) << "MITM: SRES check bypassed for " << authParams.get_SRES();
	cipher(authParams, LCH);
	LOG(DEBUG) << "MITM: a5/" << authParams.get_a5() << " cipher forced";
	return true;
    } else {
	string RES = gSubscriberRegistry.imsiGet(IMSI, "sres");
	if (RES == authParams.get_SRES()) { // verify SRES
	    LOG(DEBUG) << "Local authentication success for " << authParams.mobileID();
	    cipher(authParams, LCH);
	    return true;
	}
	LOG(ERR) << "Failed to verify SRES " << authParams.get_SRES() << " against local RES " << RES;
	return false;
    }
}

bool Control::auth_reg(GSM::L3MobileIdentity mobileID, GSM::LogicalChannel* LCH) {
    AuthenticationParameters authParams(mobileID);
    bool r, a;
    LOG(DEBUG) << "Registering " << mobileID << endl;
    switch(gConfig.getNum("GSM.Authentication")) {
    case 0: return registerIMSI(authParams, LCH);
    case 1:
	r = registerIMSI(authParams, LCH);
	a = auth_sip(authParams, LCH);
	return (r && a);
    case 2: return auth_local(authParams, LCH);
    default: return false;
    }
}
