/**
* Copyright (c) 2003-2009 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v2.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v20.html".
*/

#include "tlsconnection.h"
#include <es_sock.h>
#include <in_sock.h>

#ifdef SYMBIAN_ENABLE_SPLIT_HEADERS
#include <ssl_internal.h>
#endif

#include "mbedcontext.h"
#if defined(MBEDTLS_USE_PSA_CRYPTO)
static TBool psaInitState = EFalse;
#endif

#include <string.h>
#include <stdlib.h>
#include <escapeutils.h>

#ifndef EKA2
TInt E32Dll(TDllReason) {
	LOG(Log::Init());
	return KErrNone;
}

#ifdef SSLADAPTOR
class CSslAdaptor {
public:
	static IMPORT_C MSecureSocket* NewL(RSocket& aSocket, const TDesC& aProtocol);
};

EXPORT_C MSecureSocket* CSslAdaptor::NewL(RSocket& aSocket, const TDesC& aProtocol) {
	return CTlsConnection::NewL(aSocket, aProtocol);
}

EXPORT_C void UnloadDll(TAny* aPtr) {
	return CTlsConnection::UnloadDll(aPtr);
}

// prevent exporting below functions
#undef EXPORT_C
#define EXPORT_C

#endif
#endif

EXPORT_C MSecureSocket* CTlsConnection::NewL(RSocket& aSocket, const TDesC& aProtocol)
/**
 * Creates and initialises a new CTlsConnection object.
 * 
 * @param aSocket is a reference to an already open and connected socket.
 * @param aProtocol is a descriptor containing the name of the protocol (SSL3.0 or 
 * TLS1.0) the application specified when the secure socket was created.
 * @return A pointer to a newly created Secure socket object.
 */
{
#if defined(EKA2)
	LOG(Log::Init());
#endif
	LOG(Log::Printf(_L("CTlsConnection::NewL(RSocket)")));
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	if (!psaInitState) {
		psaInitState = ETrue;
		psa_crypto_init();
	}
#endif
	
	CTlsConnection* self = new(ELeave) CTlsConnection();

	CleanupStack::PushL(self);
	self->ConstructL(aSocket, aProtocol);
	CleanupStack::Pop();
	return self;
}

// only 9.2+
EXPORT_C MSecureSocket* CTlsConnection::NewL(MGenericSecureSocket& aSocket, const TDesC& aProtocol)
/**
 * Creates and initialises a new CTlsConnection object.
 * 
 * @param aSocket is a reference to socket like object derived from MGenericSecureSocket.
 * @param aProtocol is a descriptor containing the name of the protocol (SSL3.0 or 
 * TLS1.0) the application specified when the secure socket was created.
 * @return A pointer to a newly created Secure socket object.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::NewL(MGenericSecureSocket)")));
#if defined(EKA2)
	LOG(Log::Init());
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	if (!psaInitState) {
		psaInitState = ETrue;
		psa_crypto_init();
	}
#endif

	CTlsConnection* self = new(ELeave) CTlsConnection();

	CleanupStack::PushL(self);
	self->ConstructL(aSocket, aProtocol);
	CleanupStack::Pop();
	return self;
}

EXPORT_C void CTlsConnection::UnloadDll(TAny* /*aPtr*/)
{
	LOG(Log::Printf(_L("CTlsConnection::UnloadDll()")));
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	if (psaInitState) {
		mbedtls_psa_crypto_free();
		psaInitState = EFalse;
	}
#endif
	LOG(Log::Close());
}

CTlsConnection::~CTlsConnection()
/**
 * Destructor.
 * The user should ensure that the connection has been closed before destruction,
 * as there is no check for any pending asynch event here (apart from the panic 
 * in ~CActive).
 */
{
	LOG(Log::Printf(_L("CTlsConnection::~CTlsConnection()")));
	iDataMode = EFalse;
	if (iHandshake) {
		delete iHandshake;
		iHandshake = NULL;
	}
	if (iHandshakeEvent) {
		delete iHandshakeEvent;
		iHandshakeEvent = NULL;
	}
	if (iRecvData) {
		delete iRecvData;
		iRecvData = NULL;
	}
	if (iRecvEvent) {
		delete iRecvEvent;
		iRecvEvent = NULL;
	}
	if (iSendData) {
		delete iSendData;
		iSendData = NULL;
	}
	if (iSendEvent) {
		delete iSendEvent;
		iSendEvent = NULL;
	}
	if (iBio) {
		delete iBio;
		iBio = NULL;
	}
	if (iClientCert) {
		delete iClientCert;
		iClientCert = NULL;
	}
	if (iServerCert) {
		delete iServerCert;
		iServerCert = NULL;
	}
	if (iMbedContext) {
		delete iMbedContext;
		iMbedContext = NULL;
	}
}

CTlsConnection::CTlsConnection() : CActive(EPriorityHigh),
  iReceivingData(EFalse),
  iSendingData(EFalse),
  iHandshaking(EFalse),
  iHandshaked(EFalse)
/**
 * Constructor .
 * Sets the Active object priority.
 */
{
}

void CTlsConnection::ConstructL(RSocket& aSocket, const TDesC& /*aProtocol*/)
/** 
 * Two-phase constructor.
 * Called by CTlsConnection::NewL() to initialise all the 
 * CTlsConnection objects (bar the State machines). It also sets the 
 * protocol for the connection. The Provider interface is created and the Session
 * interface pointer is set to NULL (as no session currently exists).
 * The dialog mode for the connection is set to Attended mode (default) and the current 
 * cipher suite is set to [0x00],[0x00].
 *
 * @param aSocket is a reference to an already open and connected socket.
 * @param aProtocol is a descriptor containing the name of the protocol (SSL3.0 or 
 * TLS1.0) the application specified when the secure socket was created.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::ConstructL(1)")));
	CActiveScheduler::Add(this);

	iSocket = &aSocket;
#ifdef USE_GENERIC_SOCKET
	iIsGenericSocket = EFalse;
#endif
	
	Init();
}

void CTlsConnection::ConstructL(MGenericSecureSocket& aSocket, const TDesC& /*aProtocol*/)
/** 
 * Two-phase constructor.
 * Called by CTlsConnection::NewL() to initialise all the 
 * CTlsConnection objects (bar the State machines). It also sets the 
 * protocol for the connection. The Provider interface is created and the Session
 * interface pointer is set to NULL (as no session currently exists).
 * The dialog mode for the connection is set to Attended mode (default) and the current 
 * cipher suite is set to [0x00],[0x00].
 *
 * @param aSocket is a reference to socket like object derived from MGenericSecureSocket.
 * @param aProtocol is a descriptor containing the name of the protocol (SSL3.0 or 
 * TLS1.0) the application specified when the secure socket was created.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::ConstructL(2)")));
	CActiveScheduler::Add(this);

#ifdef USE_GENERIC_SOCKET
	iGenericSocket = &aSocket;
	iIsGenericSocket = ETrue;
#else
	iSocket = (RSocket*)&aSocket;
#endif
	
	Init();
}

inline void CTlsConnection::Init()
{
	// TODO check for error
	iMbedContext = new CMbedContext();
	iMbedContext->InitSsl();
	
	iBio = CBio::NewL(*this);

	iRecvEvent = new (ELeave) CRecvEvent(*iMbedContext, *iBio);
	iRecvData = CRecvData::NewL(*this);
	
	iSendEvent = new (ELeave) CSendEvent(*iMbedContext, *iBio);
	iSendData = CSendData::NewL(*this);
	
	iHandshakeEvent = new (ELeave) CHandshakeEvent(*iMbedContext, *iBio);
	iHandshake = CHandshake::NewL(*this);

	iDialogMode = EDialogModeAttended;
}

void CTlsConnection::RunL()
{
	LOG(Log::Printf(_L("CTlsConnection::RunL()")));
	CActiveScheduler::Stop();
}

void CTlsConnection::DoCancel()
{
	LOG(Log::Printf(_L("CTlsConnection::DoCancel()")));
}


// MSecureSocket interface
TInt CTlsConnection::AvailableCipherSuites(TDes8& aCiphers)
/** 
 * Retrieves the list of cipher suites that are available to use
 * for handshake negotiation. 
 * Cipher suites are returned in two byte format as is specified in the SSL/TLS 
 * specifications, e.g. [0x00][0x03]. 
 *
 * @param aCiphers A reference to a descriptor which will contain a list of cipher suites. 
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	// ignored
	LOG(Log::Printf(_L("CTlsConnection::AvailableCipherSuites()")));
	return KErrNone;
}

void CTlsConnection::CancelAll()
/**
 * Cancels all outstanding operations. 
 */
{
	LOG(Log::Printf(_L("+CTlsConnection::CancelAll()")));
	CancelRecv();
	CancelSend();
	if (iHandshake) {
		LOG(Log::Printf(_L("  handshake active: %d"), iHandshake->IsActive()));
		iHandshake->Cancel(KErrNone);
	}
#ifndef EKA2
	if (iQueuedSendStatus) {
		TRequestStatus* q = iQueuedSendStatus;
		iQueuedSendStatus = NULL;
		iQueuedSendDesc = NULL;
		User::RequestComplete(q, KErrCancel);
	}
	if (iQueuedSendInFlight) {
		TRequestStatus* q = iQueuedSendInFlight;
		iQueuedSendInFlight = NULL;
		User::RequestComplete(q, KErrCancel);
	}
	if (iSocket) {
		iSocket->CancelAll(); // no raw socket request may complete after we're gone
	}
#endif
	LOG(Log::Printf(_L("-CTlsConnection::CancelAll()")));
}

void CTlsConnection::CancelHandshake()
/**
 * Cancels an outstanding handshake operation. It is equivalent to
 * a CancelAll() call.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::CancelHandshake()")));
	CancelAll();
}

void CTlsConnection::CancelRecv()
/** 
 * Cancels any outstanding read data operation.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::CancelRecv()")));
	if (Busy() || iDataMode) {
#ifdef USE_GENERIC_SOCKET
		if (iGenericSocket) {
			iGenericSocket->CancelRecv();
			iGenericSocket->CancelRead();
		} else
#endif
		{
			iSocket->CancelRecv();
			iSocket->CancelRead();
		}
	}
	if (iRecvData) {
		iRecvData->Cancel(KErrNone);
	}
}

void CTlsConnection::CancelSend()
/** 
 * Cancels any outstanding send data operation.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::CancelSend()")));
	if (Busy() || iDataMode) {
#ifdef USE_GENERIC_SOCKET
		if (iGenericSocket) {
			iGenericSocket->CancelSend();
		} else
#endif
		{
			iSocket->CancelSend();
		}
	}
	if (iSendData) {
		iSendData->Cancel(KErrNone);
	}
}

const CX509Certificate* CTlsConnection::ClientCert()
/**
 * Returns a pointer to the current client certificate if a Server has
 * requested one. If there is no suitable client certificate available, a NULL pointer 
 * will be returned.
 * A client certificate (if available) can only be returned after the negotiation
 * is complete.
 *
 * @return A pointer to the client certificate, or NULL if none exists or is yet
 * available.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::ClientCert()")));
	return NULL;
}

TClientCertMode CTlsConnection::ClientCertMode()
/** 
 * Returns the current client certificate mode. This is used when the 
 * socket is acting as a server, and determines if a client certificate is requested.
 * This method is not supported as this implementation only acts in Client mode.
 *
 * The closest value that the TClientCertMode enumeration provides that supports this
 * is EClientCertModeIgnore.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::ClientCertMode()")));
	return EClientCertModeIgnore;
}

void CTlsConnection::Close()
/** 
 * Closes the secure connection.
 * All outstanding operations are cancelled, the internal state machines are deleted
 * and the socket is closed.
 */
{
	LOG(Log::Printf(_L("+CTlsConnection::Close()")));
	CancelAll();
//	if (iMbedContext) {
//		iMbedContext->SslCloseNotify();
//	}
#ifdef USE_GENERIC_SOCKET
	if (iGenericSocket) {
		iGenericSocket->Close();
	} else
#endif
	if (iSocket) {
		iSocket->Close();
	}
	iDataMode = EFalse;
	LOG(Log::Printf(_L("-CTlsConnection::Close()")));
//	Reset();
}

TInt CTlsConnection::CurrentCipherSuite(TDes8& aCipherSuite)
/**
 * Retrieves the current cipher suite in use. 
 * Cipher suites are returned in two byte format as is specified in the SSL/TLS 
 * specifications, i.e. [0x??][0x??]. 
 *
 * This method can only return the current cipher suite when the Server has proposed one
 * to use (i.e., anytime after the Server Hello has been received). Hence, it will only 
 * have a valid value after the Handshake negotiation has completed. If called before 
 * handshake negotiation, it will have the value of the NULL cipher, [0x00][0x00].
 *
 * @param aCipherSuite A reference to a descriptor at least 2 bytes long.
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	// stub
	LOG(Log::Printf(_L("CTlsConnection::CurrentCipherSuite()")));
	if (aCipherSuite.MaxLength() < 2) {
		return KErrOverflow;
	}
	aCipherSuite.SetLength(2);
	aCipherSuite[0] = 0;
	aCipherSuite[1] = 0;
	return KErrNone;
}

TDialogMode	CTlsConnection::DialogMode()
/**
 * Returns the current dialog mode.
 *
 * @return The current dialog mode.
 */ 
{
	LOG(Log::Printf(_L("CTlsConnection::DialogMode()")));
	return iDialogMode;
}

void CTlsConnection::FlushSessionCache()
/** 
 * This method does NOT flush the session cache (as this is device-wide). As such, its
 * interpretation has changed from the pre-Zephyr TLS implementation.
 *
 * It is now used as an indication that the client does not intend to reuse an existing
 * session. As such it sets a flag which is called during handshake negotiation which 
 * indicates whether a new session or existing session will be used.
 * The other choice for implementation of this method will be:
 * 1) Call TLS Provider's GetSession() API to retrieve the session information.
 * 2) Call TLS Provider's ClearSessionCache() API (with the retrieved session information) 
 * to remove the particular session from the session cache. Both these APIs are asynchronous.
 *
 * Note that there is no means of indicating the success or failure of this operation
 * to the client.
 */
{
	// TODO session cache
	LOG(Log::Printf(_L("CTlsConnection::FlushSessionCache()")));
}

TInt CTlsConnection::GetOpt(TUint aOptionName,TUint aOptionLevel,TDes8& aOption)
/**
 * Gets a Socket option. 
 *
 * @param aOptionName An unsigned integer constant which identifies an option.
 * @param aOptionLevel An unsigned integer constant which identifies the level of an option.	 
 * @param aOption Option value packaged in a descriptor.
 * @return KErrNone if successful, otherwise another of the system-wide error codes.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::GetOpt(1): %d %d"), aOptionName, aOptionLevel));
	if (aOptionLevel != KSolInetSSL) {
#ifdef USE_GENERIC_SOCKET
		if (iIsGenericSocket) {
			return iGenericSocket->GetOpt(aOptionName, aOptionLevel, aOption);
		}
#endif
		return iSocket->GetOpt(aOptionName, aOptionLevel, aOption);
	}
	return KErrNone;
}

TInt CTlsConnection::GetOpt(TUint aOptionName,TUint aOptionLevel,TInt& aOption)
/**
 * Gets a Socket option. 
 *
 * @param aOptionName An integer constant which identifies an option.
 * @param aOptionLevel An integer constant which identifies the level of an option.	 
 * @param aOption Option value as an integer.
 * @return KErrNone if successful, otherwise another of the system-wide error codes.
 */
{ 
	LOG(Log::Printf(_L("CTlsConnection::GetOpt(2)")));
	TPtr8 optionDes((TUint8*)&aOption, sizeof(TInt), sizeof(TInt));
	return GetOpt(aOptionName, aOptionLevel, optionDes);
}

TInt CTlsConnection::Protocol(TDes& aProtocol)
/**
 * Returns the Protocol version in use. A minimum descriptor size of 8 is
 * defined for the protocol name (a maximum of 32 is specified in the Secure Socket interface).
 *
 * This method can only return the agreed/negotiated Protocol anytime when the handshake 
 * negotiation has completed. If called before this, the value returned is the protocol
 * version proposed by the user.
 *
 * @param aProtocol A reference to a descriptor containing the protocol name in use.
 * @return An Integer value indicating the outcome of the function call.
 */
{
	// always returns TLS 1.0
	LOG(Log::Printf(_L("CTlsConnection::Protocol()")));
	if (aProtocol.MaxSize() < KProtocolDescMinSize) return KErrOverflow;
	aProtocol.Copy(KProtocolVerTLS10);
	return KErrNone;
}

void CTlsConnection::Recv(TDes8& aDesc, TRequestStatus & aStatus)
/**
 * Receives data from the socket. 
 * It is an asynchronous method, and will complete when the descriptor has been filled. 
 * Only one Recv or RecvOneOrMore operation can be outstanding at any time. 
 * 
 * @param aDesc A descriptor where data read will be placed.
 * @param aStatus On completion, will contain an error code: see the system-wide error 
 * codes. Note that KErrEof indicates that a remote connection is closed, and that no 
 * more data is available for reading.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::Recv()")));
	if (RecvData(aDesc, aStatus))
		iRecvData->SetSockXfrLength(NULL);
}

void CTlsConnection::RecvOneOrMore(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen)
/** 
 * Receives data from the socket. 
 * It is an asynchronous call, and will complete when at least one byte has been read.
 * Only one Recv or RecvOneOrMore operation can be outstanding at any time. 
 *
 * @param aDesc A descriptor where data read will be placed.
 * @param aStatus On completion, will contain an error code: see the system-wide error 
 * codes. Note that KErrEof indicates that a remote connection is closed, and that no 
 * more data is available for reading.
 * @param aLen On return, a length which indicates how much data was read. This is
 * the same as the length of the returned aDesc.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::RecvOneOrMore(): %d"), aDesc.MaxLength()));
	if (RecvData(aDesc, aStatus))
		iRecvData->SetSockXfrLength(&aLen());
}

void CTlsConnection::RenegotiateHandshake(TRequestStatus& aStatus)
/**
 * Initiates a renegotiation of the secure connection. 
 * It is an asynchronous method that completes when renegotiation is complete. 
 * The Client can initiate handshake renegotiation or it can receive a re-negotiation request 
 * from a remote server.
 * Note that the User should cancel any data transfer or wait for its completion before
 * attempting to re-negotiate.
 *
 * @param aStatus On completion, will contain an error code: see the system-wide error 
 * codes.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::RenegotiateHandshake()")));
	TRequestStatus* pStatus = &aStatus;
	if (!iSendData || !iRecvData || !iDataMode) {
		User::RequestComplete(pStatus, KErrNotReady);
		return;
	}
	if (Busy()) {
		User::RequestComplete(pStatus, KErrInUse);
		return;
	}
	iSendData->Suspend();
	iRecvData->Suspend();
	iRecvEvent->CancelAll();
	StartClientHandshakeStateMachine(pStatus);
}

void CTlsConnection::Send(const TDesC8& aDesc, TRequestStatus& aStatus)
/** 
 * Sends data over the socket. 
 * Only one Send operation can be outstanding at any time.
 *
 * @param aDesc A constant descriptor containing the data to be sent.
 * @param aStatus On completion, will contain an error code: see the system-wide 
 * error codes. 
 */
{
	if (SendData(aDesc, aStatus))
		iSendData->SetSockXfrLength(NULL);
}

void CTlsConnection::Send(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen)
/** 
 * Sends data over the socket. 
 * Only one Send operation can be outstanding at any time. 
 *
 * @param aDesc A constant descriptor.
 * @param aStatus On completion, will contain an error code: see the system-wide 
 * error codes. 
 * @param aLen Filled in with amount of data sent before completion 
 */
{
	if (SendData(aDesc, aStatus))
		iSendData->SetSockXfrLength(&aLen());
}

const CX509Certificate* CTlsConnection::ServerCert()
/**
 * Returns a pointer to the current server certificate.
 * The returned certificate will be the certificate for the remote server. It is 
 * obtained via the TLS Provider API.
 *
 * A server certificate (if available) can only be returned only after the 
 * negotiation has reached a stage at which one has been received and verified.
 *
 * @return A pointer to the Server's certificate.
 */ 
{
	LOG(Log::Printf(_L("CTlsConnection::ServerCert()")));
	return iServerCert;
}

TInt CTlsConnection::SetAvailableCipherSuites(const TDesC8& aCiphers)
/** 
 * A client can be involved in the Handshake negotiation with the remote server by 
 * specifying which cipher suites it wants to use in the negotiation. 
 * The client should first call AvailableCipherSuites() to retrieve all the supported
 * cipher suites. This method can then be used to specify a subset which it wants to
 * use.
 * The list of cipher suites supplied in a descriptor to the protocol MUST be in two
 * byte format, i.e. [0x??][0x??]. The order of suites is important, and so they should 
 * be listed with the preferred suites first. 
 * A client does NOT have to call/use this method. In this instance, the preference
 * order of the cipher suites will be set by the TLS Provider.
 * 
 * @param aCiphers A descriptor containing the list of ciphers suites to use. 
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::SetAvailableCipherSuites()")));
	return KErrNone;
}

TInt CTlsConnection::SetClientCert(const CX509Certificate& /*aCert*/)
/**
 * Sets the client certificate to use.
 * In client mode, this method will set the certificate that will be used if a 
 * server requests one.
 * Note that this method is NOT supported by the current implementation. Client 
 * Certificates are stored by the Security subsystem and it chooses the appropriate
 * Client certificate to use based on the Server's preference list.
 *
 * @param aCert A reference to the certificate to use.
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::SetClientCert()")));
	return KErrNone;
}

TInt CTlsConnection::SetClientCertMode(const TClientCertMode /*aClientCertMode*/)
/** 
 * Sets the client certificate mode. 
 * This method only applies to Server mode operation (which is not supported by the 
 * current implementation). In client mode, no action will be performed and 
 * KErrNotSupported will be returned by the Protocol.
 *
 * @param aClientCertMode The client certificate mode to use.
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::SetClientCertMode()")));
	return KErrNone;
}

TInt CTlsConnection::SetDialogMode(const TDialogMode aDialogMode)
/**
 * Sets the untrusted certificate dialog mode.
 * It determines if a dialog is displayed when an untrusted certificate is received.
 * The default behaviour is for the dialog to be set to EDialogModeAttended (this 
 * is set in the construction of a CTlsConnection object).
 * A client can either set the dialog mode directly by calling this method, or by
 * calling CTlsConnection::SetOpt() with an appropriate option value.
 *
 * @param aDialogMode The dialog mode to use.
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::SetDialogMode()")));
	iDialogMode = aDialogMode;
	return KErrNone;
}

TInt CTlsConnection::SetOpt(TUint aOptionName,TUint aOptionLevel, const TDesC8& aOption)
/** 
 * Sets a Socket option. 
 *
 * @param aOption Option value packaged in a descriptor.
 * @param aOptionName An integer constant which identifies an option.
 * @param aOptionLevel An integer constant which identifies the level of an option 
 * (an option level groups related options together).
 * @return Any one of the system error codes, or KErrNone on success.
 */
{
	LOG(Log::Printf(_L("CTlsConnection::SetOpt(): name: %x, level: %x, len: %d"), aOptionName, aOptionLevel, aOption.Length()));
	LOG(Log::HexDump(_S("  opt "), _S("      "), aOption.Ptr(), aOption.Length() > 64 ? 64 : aOption.Length()));
	TInt ret=KErrNotSupported;
	switch(aOptionLevel)
	{
	case KSolInetSSL:		// This is the only supported option level in SSL/TLS
	{
		switch (aOptionName)
		{
		case KSoSSLDomainName:		
			{
			if (iMbedContext) {
				// text conversion
				HBufC* buf = HBufC::NewL(aOption.Length() + 2);
				TPtr des = buf->Des();
				des.Copy(aOption); 
				
				// TODO: inetprotutil available only from 7.0
				HBufC8* converted = EscapeUtils::ConvertFromUnicodeToUtf8L(buf->Des());
				
				char* res = new char[converted->Length() + 1];
				Mem::Copy(res, converted->Ptr(), converted->Length());
				res[converted->Length()] = 0;
					
				iMbedContext->SetHostname(res);
//				delete[] res; // result is now held in mbed context
				delete buf;
			}
			ret = KErrNone;
			break;
			}
		case KSoDialogMode:
			{
			TDialogMode dialogMode = (TDialogMode) (*(TUint*)aOption.Ptr());
			ret = SetDialogMode(dialogMode);
			break;
			}
//		case KSoUseSSLv2Handshake:
//			{
//			ret = KErrNone;
//			break;
//			}
//		case KSoEnableNullCiphers:
//			{
//			ret = KErrNone;
//			break;
//			}
//		case KSoPskConfig:
//			{
//			ret = KErrNone;
//			break;
//			}
//		case 0x40a/*KSoServerNameIndication*/:
//			{
//			if(aOption.Length() < sizeof(CDesC8Array *))
//			{
//				return KErrArgument;
//			}
//			CDesC8Array *serverNames = *reinterpret_cast<CDesC8Array * const *>(aOption.Ptr());
//			ret = KErrNone;
//			break;
//			}
		default:
			ret = KErrNone;
			break;
		}
		break;
	}
	default:	// Not a supported SSL option, call RSocket::SetOpt directly
	{
#ifdef USE_GENERIC_SOCKET
		if (iIsGenericSocket) {
			ret = iGenericSocket->SetOpt(aOptionName, aOptionLevel, aOption);
		} else
#endif
		{
			ret = iSocket->SetOpt(aOptionName, aOptionLevel, aOption);
		}
		break;
	}
	}
	return ret;
}

TInt CTlsConnection::SetOpt(TUint aOptionName,TUint aOptionLevel,TInt aOption)
/** 
 * Sets a Socket option.  calls the SetOpt() method defined above.
 *
 * @param aOption Option value as an integer
 * @param aOptionName An integer constant which identifies an option.
 * @param aOptionLevel An integer constant which identifies level of an option (an
 * option level groups related options together.
 * @return Any one of the system error codes, or KErrNone on success.
 */
{
	TPtr8 optionDes((TUint8*)&aOption, sizeof(TInt), sizeof(TInt));
	return SetOpt(aOptionName, aOptionLevel, optionDes);	
}

TInt CTlsConnection::SetProtocol(const TDesC& aProtocol)
/**
 * Sets the Secure socket protocol version (SSL v3.0 or TLS v1.0) to 
 * use in the Handshake negotiation. It also initially sets the negotiated protocol 
 * to the requested protocol. A maximum length of 32 is specified in the Secure Socket 
 * interface for the protocol version.
 *
 * 
 * @param aProtocol is a reference to a descriptor containing the protocol version to use.
 * @return Any one of the system error codes, or KErrNone on success.
 */
{
	// ignored
	LOG(Log::Printf(_L("CTlsConnection::SetProtocol()")));
	return KErrNone;
}

TInt CTlsConnection::SetServerCert(const CX509Certificate& /*aCert*/)
/**
 * Reserved for future work, always returns KErrNotSupported. 
 * 
 * @param aCert The certificate to use.
 * @return Any one of the system error codes, or KErrNone on success. 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::SetServerCert()")));
	return KErrNotSupported;
}

#ifndef EKA2
// SNI fallback for clients that never pass the host name (KSoSSLDomainName), e.g. the
// MIDP HttpsConnection on S80v2: C:\System\Data\ssl_sni.txt holds lines
// "<IPv4 address> <host name>"; when the connected peer's address matches, that host
// name is used for SNI. Lines starting with # are comments.
#include <f32file.h>
_LIT(KSniMapFile, "C:\\System\\Data\\ssl_sni.txt");

static char* LookupSniHost(const TDesC8& aAddr)
{
	RFs fs;
	if (fs.Connect() != KErrNone) return NULL;
	RFile f;
	char* result = NULL;
	if (f.Open(fs, KSniMapFile, EFileRead | EFileShareReadersOnly) == KErrNone) {
		HBufC8* buf = HBufC8::New(4096);
		if (buf) {
			TPtr8 p = buf->Des();
			f.Read(p);
			TPtrC8 rest(p);
			while (rest.Length() > 0 && !result) {
				TInt nl = rest.Locate('\n');
				TPtrC8 line = nl < 0 ? rest : rest.Left(nl);
				rest.Set(nl < 0 ? TPtrC8() : rest.Mid(nl + 1));
				// trim CR and spaces
				while (line.Length() > 0 && (line[line.Length() - 1] == '\r' || line[line.Length() - 1] == ' ' || line[line.Length() - 1] == '\t'))
					line.Set(line.Left(line.Length() - 1));
				if (line.Length() == 0 || line[0] == '#') continue;
				TInt sp = line.Locate(' ');
				if (sp < 0) sp = line.Locate('\t');
				if (sp <= 0) continue;
				TPtrC8 ip = line.Left(sp);
				TPtrC8 host = line.Mid(sp + 1);
				while (host.Length() > 0 && (host[0] == ' ' || host[0] == '\t')) host.Set(host.Mid(1));
				if (host.Length() > 0 && ip.Compare(aAddr) == 0) {
					result = new char[host.Length() + 1];
					if (result) {
						Mem::Copy(result, host.Ptr(), host.Length());
						result[host.Length()] = 0;
					}
				}
			}
			delete buf;
		}
		f.Close();
	}
	fs.Close();
	return result;
}
#endif

#ifndef EKA2
// "GET /x HTTP/1.1\r\nHost: example.com:443\r\n..." -> "example.com" (new char[]),
// or NULL if aData doesn't look like an HTTP request with a Host header.
static char* HostFromHttpRequest(const TDesC8& aData)
{
	if (aData.Length() < 16 || aData[0] < 'A' || aData[0] > 'Z') return NULL;
	TInt i = 0;
	const TInt n = aData.Length();
	while (i < n) {
		TInt nl = aData.Mid(i).Locate('\n');
		if (nl < 0) break;
		i += nl + 1;
		if (n - i >= 5) {
			TPtrC8 key = aData.Mid(i, 5);
			if (key.CompareF(_L8("Host:")) == 0) {
				TInt s = i + 5;
				while (s < n && (aData[s] == ' ' || aData[s] == '\t')) s++;
				TInt e = s;
				while (e < n && aData[e] != '\r' && aData[e] != '\n' && aData[e] != ':' && aData[e] != ' ') e++;
				if (e <= s) return NULL;
				char* host = new char[e - s + 1];
				if (!host) return NULL;
				Mem::Copy(host, aData.Ptr() + s, e - s);
				host[e - s] = 0;
				return host;
			}
		}
		if (n - i >= 2 && aData[i] == '\r' && aData[i + 1] == '\n') break; // end of headers
	}
	return NULL;
}
#endif

void CTlsConnection::StartClientHandshake(TRequestStatus& aStatus)
/**
 * Starts a client request and initiates a handshake 
 * with the remote server.
 * Configuration retrieval happens during construction of the CTlsConnection object,
 * which progresses the connection into the Idle state. 
 *
 * @param aStatus On completion, any one of the system error codes, or KErrNone 
 * on success (handshake negotiation complete). 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::StartClientHandshake()")));
#ifndef EKA2
	if (iMbedContext && iSocket) {
		TInetAddr remote;
		iSocket->RemoteName(remote);
		TBuf<64> addr16;
		remote.Output(addr16);
		TBuf8<64> addr;
		addr.Copy(addr16);
		LOG(Log::Printf(_L("  peer %S port %d, hostname %s"), &addr16, remote.Port(),
			iMbedContext->Hostname() ? _S("set") : _S("NOT SET")));
		if (iMbedContext->Hostname() == NULL) {
			char* host = LookupSniHost(addr);
			if (host) {
				LOG(Log::Printf8(_L8("  SNI from ssl_sni.txt: %s"), host));
				iMbedContext->SetHostname(host);
			}
		}
		if (iMbedContext->Hostname() == NULL && !iHandshaked && !iDataMode && !Busy()) {
			// postpone the real handshake until the first Send (see SendData)
			LOG(Log::Printf(_L("  no host name: handshake deferred until first Send")));
			iDeferredHandshake = ETrue;
			TRequestStatus* p = &aStatus;
			User::RequestComplete(p, KErrNone);
			return;
		}
		else {
			LOG(Log::Printf8(_L8("  SNI: %s"), iMbedContext->Hostname()));
		}
	}
#endif
	TRequestStatus* pStatus = &aStatus;
	if (iDataMode || Busy()) {
		User::RequestComplete(pStatus, KErrInUse);
		return;
	}
	StartClientHandshakeStateMachine(pStatus);
}

void CTlsConnection::StartServerHandshake(TRequestStatus& aStatus)
/**
 * Start acting as a server and listen for a handshake from the remote client.
 * This is an asynchronous call, and will only complete when a client completes the 
 * handshake, or if it fails.
 * Normally, the socket passed in will usually have been previously used in a call to 
 * Accept() on a listening socket, but this is not required. 
 * Note that this implementation does not support Server mode operation, so this method
 * is NOT supported.
 *
 * @param aStatus On completion, any one of the system error codes, or KErrNone on success. 
 */
{
	LOG(Log::Printf(_L("CTlsConnection::StartServerHandshake()")));
	TRequestStatus* pStatus = &aStatus;

	User::RequestComplete(pStatus, KErrNotSupported);
}



//MStateMachineNotify interface
TBool CTlsConnection::OnCompletion(CStateMachine* aStateMachine)
{
	LOG(Log::Printf(_L("CTlsConnection::OnCompletion()")));
	if (aStateMachine == iSendData) {
		iSendingData = EFalse;
		if (iQueuedSendInFlight) {
			TRequestStatus* q = iQueuedSendInFlight;
			iQueuedSendInFlight = NULL;
			User::RequestComplete(q, aStateMachine->LastError());
		}
		else if (iQueuedSendStatus && aStateMachine->LastError() == KErrNone) {
			// start the Send that arrived during the deferred handshake; the state
			// machine runs without a client status, we complete the queued one ourselves
			TRequestStatus* first = aStateMachine->ClientStatus();
			iSendData->SetClientStatus(NULL);
			if (first) User::RequestComplete(first, KErrNone);
			iQueuedSendInFlight = iQueuedSendStatus;
			const TDesC8* d = iQueuedSendDesc;
			iQueuedSendStatus = NULL;
			iQueuedSendDesc = NULL;
			LOG(Log::Printf(_L("  sending the queued Send")));
			iSendingData = ETrue;
			iSendEvent->SetUserData((TDesC8*) d);
			iSendEvent->ResetCurrentPos();
			iSendData->Start(NULL, this);
			return EFalse;
		}
	} else if (aStateMachine == iRecvData) {
		iReceivingData = EFalse;
	} else if (aStateMachine == iHandshake) {
		iHandshaking = EFalse;
		if (aStateMachine->LastError() == KErrNone) {
			iHandshaked = ETrue;
			
			if (iDataMode) { // renegotiation
				iSendData->Resume();
				iRecvData->Resume();
				
				if (iSendData->ClientStatus()) {
					iSendData->Start(iSendData->ClientStatus(), this);
				}
				
				if (!iRecvData->IsActive() && iRecvData->ClientStatus()) {
					iRecvData->Start(iRecvData->ClientStatus(), this);
				}
			} else if (!iDataMode) {
				iDataMode = ETrue;

				iSendData->Resume();
				iRecvData->Resume();
				if (iDeferredHandshake) {
					iDeferredHandshake = EFalse;
					if (iSendData->ClientStatus()) {
						iSendingData = ETrue;
						iSendEvent->ResetCurrentPos();
						iSendData->Start(iSendData->ClientStatus(), this);
					}
				}
			}
		} else {
			// handshake failed
//			Reset();
			iHandshaked = EFalse;
			if (iDeferredHandshake) {
				iDeferredHandshake = EFalse;
				TRequestStatus* p = iSendData->ClientStatus();
				if (p) {
					iSendData->SetClientStatus(NULL);
					User::RequestComplete(p, aStateMachine->LastError());
				}
				if (iQueuedSendStatus) {
					TRequestStatus* q = iQueuedSendStatus;
					iQueuedSendStatus = NULL;
					iQueuedSendDesc = NULL;
					User::RequestComplete(q, aStateMachine->LastError());
				}
			}
		}
	}
	return EFalse;
}

TBool CTlsConnection::SendData(const TDesC8& aDesc, TRequestStatus& aStatus)
/**
 * Starts the Application data transmission state machine, 
 * which sends data to a remote Server.
 *
 * @param aDesc Reference to the user's descriptor (data buffer)
 * @param aClientStatus TRequestStatus object that completes when data transmission
 * is finished.
 */
{
	TRequestStatus* pStatus = &aStatus;
	if (!iSendData) {
		User::RequestComplete(pStatus, KErrNotReady);
		return EFalse;
	}
	if (iSendingData) {
		LOG(Log::Printf(_L("CTlsConnection::Send(1) Busy")));
		User::RequestComplete(pStatus, KErrInUse);
		return EFalse;
	}
	LOG(Log::Printf(_L("CTlsConnection::Send(1)")));
	if (!iHandshaked) {
#ifndef EKA2
		if (iDeferredHandshake && iHandshaking && iSendData->ClientStatus()) {
			// the first Send is still waiting for the handshake: queue this one
			if (iQueuedSendStatus) {
				LOG(Log::Printf(_L("  Send while 2 already queued: KErrInUse")));
				User::RequestComplete(pStatus, KErrInUse);
				return EFalse;
			}
			LOG(Log::Printf(_L("  Send queued until the deferred handshake completes")));
			aStatus = KRequestPending;
			iQueuedSendDesc = &aDesc;
			iQueuedSendStatus = &aStatus;
			return EFalse;
		}
#endif
		iSendData->SetUserData((TDesC8*) &aDesc);
		iSendData->SetClientStatus(&aStatus);
#ifndef EKA2
		if (iDeferredHandshake && !iHandshaking) {
			aStatus = KRequestPending;
			char* host = HostFromHttpRequest(aDesc);
			if (host) {
				LOG(Log::Printf8(_L8("  SNI from HTTP Host header: %s"), host));
				iMbedContext->SetHostname(host);
			} else {
				LOG(Log::Printf(_L("  no Host header in first Send, handshake without SNI")));
			}
			StartClientHandshakeStateMachine(NULL);
		}
#endif
	} else {
		iSendingData = ETrue;
		iSendEvent->SetUserData((TDesC8*) &aDesc);
		iSendEvent->ResetCurrentPos();

		iSendData->Start(pStatus, this);
	}
	
	return ETrue;
}

TBool CTlsConnection::RecvData(TDes8& aDesc, TRequestStatus& aStatus)
/**
 * Starts the Application data reception state machine, 
 * which receives data from a remote Server.
 *
 * @param aDesc Reference to the user's descriptor (data buffer)
 * @param aClientStatus TRequestStatus object that completes when data reception is 
 * finished.
 */
{
	TRequestStatus* pStatus = &aStatus;
	if (!iRecvData) {
		User::RequestComplete(pStatus, KErrNotReady);
		return EFalse;
	}
	if (iReceivingData) {
		LOG(Log::Printf(_L("CTlsConnection::RecvOneOrMore() Busy")));
		User::RequestComplete(pStatus, KErrInUse);
		return EFalse;
	}
	iReceivingData = ETrue;
	
	// Recv/RecvOneOrMore replace the descriptor's contents (like RSocket does). Without
	// this, a reused full buffer (Java reads in 512-byte chunks) leaves no room, the read
	// returns 0 bytes and is reported as KErrEof ("Unexpected end of stream").
	aDesc.Zero();
	iRecvEvent->SetUserData(&aDesc);
	iRecvEvent->SetUserMaxLength(aDesc.MaxLength());
	
	iRecvData->Start(pStatus, this);
	
	return ETrue;
}

void CTlsConnection::StartClientHandshakeStateMachine(TRequestStatus* aStatus)
/**
 * Creates and starts the Handshake negotiation state machine, 
 * which initiates negotiations with the remote Server.
 */
{
	if (!iHandshake) {
		User::RequestComplete(aStatus, KErrNotReady);
		return;
	}
	
	iHandshake->Resume();
	iHandshake->Start(aStatus, this);
	iHandshaking = ETrue;
}

//void CTlsConnection::Reset() {
//	if (iMbedContext) {
//		iMbedContext->Reset();
//	}
//}

