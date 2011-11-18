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

#include <GSMLogicalChannel.h>
#include <GSML3Message.h>
#include <GSML3CCMessages.h>
#include <GSML3RRMessages.h>
#include <GSML3MMMessages.h>
#include <GSMConfig.h>

#include <SIPEngine.h>
#include <SIPInterface.h>

#include <Logger.h>
#undef WARNING


using namespace std;
using namespace GSM;
using namespace Control;

KiTable gKiTable;

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

void KiTable::setFrameNumber(uint32_t FN){
	frameNumber=FN;
}

uint32_t KiTable::getFrameNumber(){
	return frameNumber;
}

bool KiRecord::load(FILE* fp) {
  
	/*
	 * fix - Ki cannot be returned as unsigned, can be stored in Byte array only
	 * next fix: load should return bool value indicating correct line format
	 *
	 * current file format is following;
	 * <IMSI> <Ki>
	 * possible file verification: check count of chars, digits
	 *
	 * in the end, database would be handsome
	 */

    char IMSI[16];
    char Ki[33];
	fscanf(fp, "%15s %32s\n",IMSI, Ki);
	LOG(DEBUG) << "Reading IMSI=" << IMSI << " Ki=" << Ki;
    mIMSI = IMSI;
    mKi = Ki;
    return true;
}


int KiTable::hextoint(char x) {//FIXME - use standard function
    x = toupper(x);
    if (x >= 'A' && x <= 'F')
        return x - 'A' + 10;
    else if (x >= '0' && x <= '9')
        return x - '0';
    exit(1);
}

bool KiTable::loadAndFindKI(const char* IMSI) {
    const char* filename = gConfig.getStr("Control.KiTable.SavePath").c_str();
    FILE* fp = fopen(filename, "r");
    const unsigned char *KiSigned;
    bool IMSIfound = 0;

    LOG(INFO) << "Loading data from " << filename << ", searching IMSI=" << IMSI;
    mLock.lock();
    while (!feof(fp)) {

        KiRecord val; // todo: initiate instance out of cycle and handle destructor
        val.load(fp);
        if (!strcmp(val.IMSI(), IMSI)) {
			LOG(INFO) << "IMSI:" << IMSI << " found in table, authorization process can continue";
			IMSIfound = 1;
            KiSigned = val.Ki();
			LOG(INFO) << "Ki=" << KiSigned;
            for (int i = 0; i < 16; i++){
                Ki[i] = (hextoint(KiSigned[2 * i]) << 4) | hextoint(KiSigned[2 * i + 1]);
                /* cast to unsigned is necessary, else is displayed corrupted value  */
				LOG(DEBUG) << "Converting Ki to unsigned: " << (unsigned) Ki[i]; //
			}
            break;
        }
		
        // if (!key) break; //no use, load returns currently 0
    }
	mLock.unlock();
    fclose(fp);
    if (!IMSIfound) {
    	LOG(INFO) << "IMSI="<< IMSI << " not found, skip authorization process";
    	return 0;
    } else
    	return 1;
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
	if (mobID.type()==IMSIType) {
		gKiTable.loadAndFindKI(mobID.digits());
		return gKiTable.getKi();}
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
