// Copyright (c) 1997-2009 Nokia Corporation and/or its subsidiary(-ies).
// All rights reserved.
// This component and the accompanying materials are made available
// under the terms of "Eclipse Public License v2.0"
// which accompanies this distribution, and is available
// at the URL "http://www.eclipse.org/legal/epl-v20.html".
//
// Initial Contributors:
// Nokia Corporation - initial contribution.
//
// Contributors:
//
// Description:
//

#include <e32std.h>
#include <e32base.h>
#ifdef EKA2
#include <e32debug.h>
#else
#include <e32svr.h>
#endif
#include "LOGFILE.H"

#if defined(__TRACEFILE__)

const TInt KHexDumpWidth = 16;

#ifdef SSL_LOG
#include <f32file.h>
_LIT(KSSLLogPath, "C:\\Logs\\SSL\\SSLLog.txt");

// Appends one line "hh:mm:ss.mmm [thread] text" to C:\Logs\SSL\SSLLog.txt.
// The file is opened and closed for every line, so it survives a crash or a frozen phone,
// and several processes (browser, Java) can log at the same time.
struct TSslLogFile {
	RFs fs;
	RFile f;
	TInt lines;
};

// One open file per thread (kept in the DLL's thread-local storage): opening and closing
// the file for every line made each log line cost tens of milliseconds and slowed the
// whole TLS stack down. Closed in Log::Close (when the DLL is unloaded).
static TSslLogFile* SslLogFile()
{
	TSslLogFile* lf = (TSslLogFile*) Dll::Tls();
	if (lf) return lf;
	lf = new TSslLogFile;
	if (!lf) return NULL;
	if (lf->fs.Connect() != KErrNone) {
		delete lf;
		return NULL;
	}
	TInt r = lf->f.Open(lf->fs, KSSLLogPath, EFileWrite | EFileShareAny);
	if (r == KErrNotFound) r = lf->f.Create(lf->fs, KSSLLogPath, EFileWrite | EFileShareAny);
	if (r != KErrNone) { // e.g. C:\Logs\SSL doesn't exist: no logging
		lf->fs.Close();
		delete lf;
		return NULL;
	}
	lf->lines = 0;
	Dll::SetTls(lf);
	return lf;
}

static void SslLogAppend(const TDesC8& aLine)
{
	TSslLogFile* lf = SslLogFile();
	if (!lf) return;
	TBuf8<64> pre;
	TTime now;
	now.HomeTime();
	TDateTime dt = now.DateTime();
	pre.Format(_L8("%02d:%02d:%02d.%03d [%x] "), dt.Hour(), dt.Minute(), dt.Second(),
		dt.MicroSecond() / 1000, (TUint) RThread().Id());
	TInt pos = 0;
	lf->f.Seek(ESeekEnd, pos); // other threads (browser, Java) append to the same file
	lf->f.Write(pre);
	lf->f.Write(aLine);
	lf->f.Write(_L8("\r\n"));
	if (++lf->lines % 16 == 0) lf->f.Flush();
}

static void SslLogClose()
{
	TSslLogFile* lf = (TSslLogFile*) Dll::Tls();
	if (!lf) return;
	lf->f.Flush();
	lf->f.Close();
	lf->fs.Close();
	delete lf;
	Dll::SetTls(NULL);
}
#endif

#if !defined(SSL_LOG)
#define DYNAMIC
struct LogGlobal {
	RLibrary lib;
	void(*Logger_Write16)(const TDesC&, const TDesC&, TFileLoggingMode, const TDesC16&);
	void(*Logger_Write8)(const TDesC&, const TDesC&, TFileLoggingMode, const TDesC8&);
};
#endif

void Log::Init()
{
#ifdef SSL_LOG
	TFileName name = RProcess().FileName();
	TBuf8<0x100> b;
	b.Copy(_L8("Log::Init process="));
	b.Append(name.Right(0x80 < name.Length() ? 0x80 : name.Length()));
	SslLogAppend(b);
#endif
#ifdef DYNAMIC
	LogGlobal* global = (LogGlobal*)Dll::Tls();
	if (global) return;
	
	global = new LogGlobal;
	if (!global) return;
	
	if (global->lib.Load(_L("comsdbgutil.dll")) == KErrNone) {
		global->Logger_Write16 = (void(*)(const TDesC& , const TDesC& , TFileLoggingMode , const TDesC16& ))global->lib.Lookup(12);
		global->Logger_Write8 = (void(*)(const TDesC& , const TDesC& , TFileLoggingMode , const TDesC8& ))global->lib.Lookup(24);
	} else {
		global->Logger_Write16 = NULL;
		global->Logger_Write8 = NULL;
	}
//	global->lib.Close();
	
	Dll::SetTls(global);
#endif
}

void Log::Close()
{
#ifdef SSL_LOG
	SslLogClose();
#endif
#ifdef DYNAMIC
	LogGlobal* global = (LogGlobal*)Dll::Tls();
	if (global) {
		global->lib.Close();
		delete global;
		Dll::SetTls(NULL);
	}
#endif
}

void Log::Write(const TDesC& aDes)
	{
#ifdef DYNAMIC
	LogGlobal* global = (LogGlobal*)Dll::Tls();
	if (global && global->Logger_Write16 != NULL) {
		global->Logger_Write16(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
	}
#elif defined(SSL_LOG)
	TBuf8<0x200> b;
	b.Copy(aDes.Left(0x200));
	SslLogAppend(b);
#else
	RFileLogger::Write(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
#endif
	}

void Log::Write8(const TDesC8& aDes)
	{
#ifdef DYNAMIC
	LogGlobal* global = (LogGlobal*)Dll::Tls();
	if (global && global->Logger_Write8 != NULL) {
		global->Logger_Write8(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
	}
#elif defined(SSL_LOG)
	SslLogAppend(aDes);
#else
	RFileLogger::Write(KSSLLogDir,KSSLLogFileName,EFileLoggingModeAppend,aDes);
#endif
	}


void Log::Printf(TRefByValue<const TDesC> aFmt, ...)
	{
    //coverity[var_decl];
    VA_LIST list;
    VA_START(list, aFmt);
	TBuf<0x100> buf;
    //coverity[uninit_use_in_call];
    buf.FormatList(aFmt, list);
	Write(buf);
#ifdef EKA2
	RDebug::RawPrint(buf);
#endif
	}
void Log::Printf8(TRefByValue<const TDesC8> aFmt, ...)
	{
    //coverity[var_decl];
    VA_LIST list;
    VA_START(list, aFmt);
	TBuf8<0x100> buf;
    //coverity[uninit_use_in_call];
    buf.FormatList(aFmt, list);
	Write8(buf);
#ifdef EKA2
	RDebug::RawPrint(buf);
#endif
	}

void Log::HexDump(const TText* aHeader, const TText* aMargin, const TUint8* aPtr, TInt aLen)
	{

	TBuf<0x100> buf;
	buf.SetLength(0);
	TInt i = 0;
	const TText* p = aHeader;
	while (aLen>0)
		{
		TInt n = aLen>KHexDumpWidth ? KHexDumpWidth : aLen;
		buf.AppendFormat(_L("%s%04x : "), p, i);
		TInt j;
		for (j=0; j<n; j++)
			buf.AppendFormat(_L("%02x "), aPtr[i+j]);
		while (j++<KHexDumpWidth)
			buf.AppendFormat(_L("   "));
		buf.AppendFormat(_L(" "));
		for (j=0; j<n; j++)
			buf.AppendFormat(_L("%c"), aPtr[i+j]<32 || aPtr[i+j]>126 ? '.' : aPtr[i+j]);
		buf.AppendFormat(_L("\r\n"));
		Log::Write(buf);
		buf.SetLength(0);
		aLen -= n;
		i += n;
		p = aMargin;
		}
	}


#endif // __TRACEFILE__
