/*
 * Twain.c
 *
 * This module contains the code for making a the python 
 * classes.
 *
 * Copyright - GNU Format, See Documentation
 *
 * $Id: twain.C,v 1.14 2010/06/08 23:07:42 kevin_gill Exp $
 */

#define TRACE 0
#define ENABLE_BUFFER_CHECK 0

static char *gszVersion="1.0";

#include <windows.h>            // Req. for twain.h type defs and ...
#include <strsafe.h>            // For StringCchCopy()

#include <twain.h>         // In the Twain SDK

//	Necessary Prototype
static TW_FIX32 FloatToFix32 (double floater);
static double Fix32ToFloat(TW_FIX32 *pFix32);
static void DeclareWindowClass();
static HWND CreateWindowInstance(HWND hWndParent);
static void DestroyWindowInstance(HWND hWnd);


// Extra constants
static char *pDSMNAME="TWAIN_32.DLL";
#define WINDIRPATHSIZE 160
#define VALID_HANDLE    32      // valid windows handle SB >= 32

#include <Python.h>

// Python 2.1
#ifndef METH_NOARGS
#define METH_NOARGS METH_VARARGS
#endif


// Exception Objects
static PyObject *excSMLoadFileFailed;
static PyObject *excSMGetProcAddressFailed;
static PyObject *excSMOpenFailed;
static PyObject *excDSOpenFailed;
static PyObject *excDSNoImageAvailable;
static PyObject *excDSTransferCancelled;
static PyObject *excCapabilityFormatNotSupported;
static PyObject *excBufferOverrun;
static PyObject *excGlobalHeap;
static PyObject *excImageFormat;
static PyObject *excFileError;
static PyObject *excMemoryError;
static PyObject *excParamError;
static PyObject *excInternalError;


static PyObject *excTWCC_SUCCESS;            /* It worked!                                */
static PyObject *excTWCC_BUMMER;             /* Failure due to unknown causes             */
static PyObject *excTWCC_LOWMEMORY;          /* Not enough memory to perform operation    */
static PyObject *excTWCC_NODS;               /* No Data Source                            */
static PyObject *excTWCC_MAXCONNECTIONS;     /* DS is connected to max possible applications      */
static PyObject *excTWCC_OPERATIONERROR;     /* DS or DSM reported error, application shouldn't   */
static PyObject *excTWCC_BADCAP;             /* Unknown capability                        */
static PyObject *excTWCC_BADPROTOCOL;        /* Unrecognized MSG DG DAT combination       */
static PyObject *excTWCC_BADVALUE;           /* Data parameter out of range              */
static PyObject *excTWCC_SEQERROR;           /* DG DAT MSG out of expected sequence      */
static PyObject *excTWCC_BADDEST;            /* Unknown destination Application/Source in DSM_Entry */
static PyObject *excTWCC_CAPUNSUPPORTED;     /* Capability not supported by source            */
static PyObject *excTWCC_CAPBADOPERATION;    /* Operation not supported by capability         */
static PyObject *excTWCC_CAPSEQERROR;        /* Capability has dependancy on other capability */
static PyObject *excTWCC_DENIED;             /* File System operation is denied (file is protected) */
static PyObject *excTWCC_FILEEXISTS;         /* Operation failed because file already exists. */
static PyObject *excTWCC_FILENOTFOUND;       /* File not found */
static PyObject *excTWCC_NOTEMPTY;           /* Operation failed because directory is not empty */
static PyObject *excTWCC_PAPERJAM;           /* The feeder is jammed */
static PyObject *excTWCC_PAPERDOUBLEFEED;    /* The feeder detected multiple pages */
static PyObject *excTWCC_FILEWRITEERROR;     /* Error writing the file (meant for things like disk full conditions) */
static PyObject *excTWCC_CHECKDEVICEONLINE;  /* The device went offline prior to or during this operation */
static PyObject *excTWCC_UNKNOWN;            /* Source specific Value */


// Source Manager

staticforward PyTypeObject SourceManagerType;
staticforward PyTypeObject SourceType;


typedef struct {
    PyObject_HEAD
	enum {SM_CLOSED, SM_OPEN } state;
	HANDLE     hDSMDLL;
	DSMENTRYPROC  lpDSM_Entry;
	TW_IDENTITY appID;          // storage for App states
	HWND hWnd;                  // application window handle
	void *pActiveSource;		// actually a SourceObject *
	HWND hWndPseudo;			// pseudo window to get event loop control	

	PyThreadState *threadCallback;   // thread for use with the callback
	PyObject *pfnCallback;      // Use callback function
	char szUnused[4096];
} SourceManagerObject, *pSourceManagerObject;

typedef struct {
    PyObject_HEAD
	TW_IDENTITY appID;          // storage for App states
	SourceManagerObject *pSM;	// all comms are through SM
	int bEnabled;               // Flag to indicate source is enabled
	TW_USERINTERFACE twUI;		// User info status (set during BeginAcquire)
	char szUnused[4096];
} SourceObject, *pSourceObject;

#define MAX_SD_OBJECTS 10
#define MAX_SM_OBJECTS 10

static pSourceObject AllSDObjects[MAX_SD_OBJECTS];
static pSourceManagerObject AllSMObjects[MAX_SM_OBJECTS];

//	Prototypes dependent on above definitions
static PyObject *Source_MapTWCCToException(SourceObject *Source, char *szValue);
static void kill_Source(SourceObject* Source, boolean bHaveInterp);
static void kill_SourceManager(SourceManagerObject* SourceManager, boolean bHaveInterp);

#define PRE_BUF_SIZE 8
#define BUF_SIZE 2047
#define CHECK_SIZE 8
static struct {
	char pPreBuf[PRE_BUF_SIZE];
	char pBuf[BUF_SIZE];
} CB;

static int
CallEntryPoint(
	DSMENTRYPROC lpDSM_Entry,
	TW_IDENTITY *pIdSM,
	TW_IDENTITY *pIdDS,
	TW_UINT32 iDataGroup,
	TW_UINT16 iDataItemType,
	TW_UINT16 iMessage,
	TW_MEMREF pDataBuf,
	int iBufSize,
	int *pyErr,
	boolean bHaveInterp)
{
	//	I use this method to call the data source entry-point
	//	It checks for buffer overrun, incase I pass in the wrong
	//	parameters.

	int twRC;

#if TRACE
printf("CallEntryPoint(...,0x%lx, 0x%x, 0x%x, ...), thread %d\n", iDataGroup,
	 iDataItemType, iMessage, GetCurrentThreadId());
#endif 

	if (iBufSize == -1 || pDataBuf == NULL) {
		if (bHaveInterp) {
			Py_BEGIN_ALLOW_THREADS
			twRC = lpDSM_Entry(pIdSM, pIdDS, iDataGroup, iDataItemType,
				iMessage, (TW_MEMREF)pDataBuf);
			Py_END_ALLOW_THREADS
		}
		else {
			twRC = lpDSM_Entry(pIdSM, pIdDS, iDataGroup, iDataItemType,
				iMessage, (TW_MEMREF)pDataBuf);
		}
	}
	else {
#if ENABLE_BUFFER_CHECK
		memset(&CB, 'Z', sizeof(CB));
#endif
		if (pDataBuf)
			memcpy(CB.pBuf, pDataBuf, iBufSize);

		if (bHaveInterp) {
			Py_BEGIN_ALLOW_THREADS
			twRC = lpDSM_Entry(pIdSM, pIdDS, iDataGroup, iDataItemType,
				iMessage, (TW_MEMREF)CB.pBuf);
			Py_END_ALLOW_THREADS
		}
		else {
			twRC = lpDSM_Entry(pIdSM, pIdDS, iDataGroup, iDataItemType,
				iMessage, (TW_MEMREF)CB.pBuf);
		}
#if ENABLE_BUFFER_CHECK
		{
			int i;
			char szMessage[100];
			//	Check for buffer under/overrun
			for (i=0; i< PRE_BUF_SIZE; i++) 
				if (CB.pPreBuf[i] != 'Z') {
					sprintf(szMessage, "Buffer Underrun at %d, message %d/%d/%d", 
						PRE_BUF_SIZE -i, iDataGroup, iDataItemType, iMessage); 
					PyErr_SetString(excBufferOverrun, szMessage);
					*pyErr = 1;
					break;
				}
			// Only check if app pass us in a buffer.
			if (iBufSize) {
				// Only check the first CHECK_SIZE bytes.
				for (i=iBufSize; i< BUF_SIZE && (i - iBufSize) < CHECK_SIZE; i++) 
					if (CB.pBuf[i] != 'Z') {
						sprintf(szMessage, "Buffer overrun at %d, message %d/%d/%d", 
							i, iDataGroup, iDataItemType, iMessage);
						PyErr_SetString(excBufferOverrun, szMessage);
						*pyErr = 1;
						break;
					}
			}
		}
#endif
		if (pDataBuf)
			memcpy(pDataBuf, CB.pBuf, iBufSize);
	}

#if TRACE
printf("CallEntryPoint() returning %d\n", twRC);
#endif 

	return twRC;
}

static char *pDIBToBMFile_doc = 
"Convert a DIB (Device Independent Bitmap) to a windows \n"
"bitmap file format. The BitMap file is either returned as\n"
"a string, or written to a file with the name given in the \n"
"second argument.\n";

static PyObject *
DIBToBMFile(SourceObject *Source, PyObject *args)
{
	int  twRC = TWRC_FAILURE;
	LPBITMAPINFOHEADER lpDib;
	int iSize;
	PyObject *rv;
	BITMAPFILEHEADER BitMapFileHeader;
	char *m;
	HANDLE hBitmap;
	int rowBytes;
	int iColours;
	char *szFileName = NULL;
	FILE *fp = NULL;
	char szMessage[100];

	if (!PyArg_ParseTuple(args,"l|s:DIBToBMFile", &hBitmap, &szFileName))
		return NULL;

	if ((lpDib = (LPBITMAPINFOHEADER) GlobalLock(hBitmap)) == NULL){
        unsigned long lError = GetLastError();
		sprintf(szMessage, "Could Not Lock Bitmap Memory [0x%lx], error %ld", hBitmap, lError);
		PyErr_SetString(excGlobalHeap, szMessage);
		return(NULL);
	}

	// The DIB data area is made up of the header, the colour
	// table and the bitmap. I want to convert the whole thing
	// to a string, and return it to the application.

	// Calculation from MSDN CD.
	rowBytes = (((lpDib->biWidth * lpDib->biBitCount) + 31) & ~31) >> 3;

	// Taken from MSDN
	if (!(iColours = lpDib->biClrUsed))
		if (lpDib->biBitCount != 24)
			iColours = 1 << lpDib->biBitCount;

	if (lpDib->biSizeImage == 0) {
		lpDib->biSizeImage = rowBytes * lpDib->biHeight;
	}

	if (lpDib->biCompression != BI_RGB) {
		sprintf(szMessage, "Cannot handle compressed image. Compression Format %d",
            lpDib->biCompression);
		PyErr_SetString(excImageFormat, szMessage);
	    GlobalUnlock(hBitmap);
		return NULL;
	}

	iSize = lpDib->biSize +							// Header Size
		(iColours * sizeof(RGBQUAD))				// Colour Map Size
		+ lpDib->biSizeImage;						// Image Size

	BitMapFileHeader.bfType = 0x4d42;  // "BM"
	BitMapFileHeader.bfReserved1 = 0;
	BitMapFileHeader.bfReserved2 = 0;
	BitMapFileHeader.bfSize = sizeof(BitMapFileHeader) + iSize;
	BitMapFileHeader.bfOffBits = sizeof(BitMapFileHeader) + 
		lpDib->biSize + (iColours * sizeof(RGBQUAD));

	if (szFileName) {
		fp = fopen(szFileName, "wb");
		if (!fp) {
			sprintf(szMessage, "Open Failed: [%.60s]", szFileName);
			PyErr_SetString(excFileError, szMessage);
	        GlobalUnlock(hBitmap);
			return NULL;
		}
		fwrite(&BitMapFileHeader, sizeof(BitMapFileHeader), 1, fp);
		fwrite((void *)lpDib, iSize, 1, fp);
		fclose(fp);
		Py_INCREF(Py_None);
		rv = Py_None;
	}
	else {
		m = malloc(BitMapFileHeader.bfSize);
		if (!m) {
			sprintf(szMessage, "malloc() Failed: %d bytes", BitMapFileHeader.bfSize);
			PyErr_SetString(excMemoryError, szMessage);
	        GlobalUnlock(hBitmap);
			return NULL;
		}
		memcpy(m, &BitMapFileHeader, sizeof(BitMapFileHeader));
		memcpy(m + sizeof(BitMapFileHeader), (void *)lpDib, iSize);

		rv = Py_BuildValue("z#", m, BitMapFileHeader.bfSize);
		free(m);
	}

	GlobalUnlock(hBitmap);
	return rv;
}

static int
iGetDIBBit(char *pDIB, int biBitCount, int biWidth, int biHeight, int x, int y)
{
	int iScanLineOffset;
	int iScanLineSize;
	int iOffset, iByte, iMask, iBit;
	int iRv;
	long iByte0, iByte1, iByte2, lByte;

	//	Extract a single bit from a DIB bitmap, for
	//	a given x,y location.

	//	The DIB file is store with 0,0 at the end of the file.
	iScanLineSize = (((biWidth * biBitCount) + 31) & ~31) >> 3;
	iScanLineOffset = (biHeight - (x+1)) * iScanLineSize;

	switch (biBitCount) 
	{
	default: // try this for anything else
	case 1:
		iRv = 0;
		//	Find the bit, from the iScanLineOffset, which contains our bit.
		iOffset = (y * biBitCount)/8;
		iBit = 7 - ((y * biBitCount)%8);
		iByte = pDIB[iScanLineOffset + iOffset];
		iMask = 1 << iBit;
		iByte &= iMask;
		iRv =  (iByte >> iBit) &0x1 ? 0:1;
		return iRv;
	case 8:
		iOffset = (y * biBitCount)/8;
		iByte = (pDIB[iScanLineOffset + iOffset]) &0xFF;
		return iByte >= 0x80 ? 0:1;
	case 24:
		iOffset = (y * biBitCount)/8;
		iByte0 = (pDIB[iScanLineOffset + iOffset + 0]) &0xFF;
		iByte1 = (pDIB[iScanLineOffset + iOffset + 1]) &0xFF;
		iByte2 = (pDIB[iScanLineOffset + iOffset + 2]) &0xFF;
		lByte = (iByte0) | (iByte1 << 8) | (iByte2 << 16);
		return lByte >= 0x800000L ? 0:1;	
	}
	return 0;
}


//	The XBM Format is a 'C' code representation of a image.
//	Line 1 = #define XXX_width val
//	Line 2 = #define XXX_height val
//	Line 3 = static char XXX_bits[] = {
//	Rest of file = lines defining 8bit values, 12 values 
//		per line. last line has }; suffixed.
//
//	0=white, 1=black
//	Lines are aligned to byte.
//
//	DIB File Format...
//	Header
//	Colour Map
//	Bits
//	Bits are broken into scanlines, with the scanline length
//	rounded to 32bit boundary.
//
//	1=white, 0=black : for single colour bit map
//
//	Line information is left aligned in the scanline section
//	i.e. it is padded to the right.
//
//	Bits are represented in the buffer, left to right, i.e.
//	byte 0 represents first 8 bits on the line, bit 0 (MSB)
//	represents bit 0 on the line.


static char *pDIBToXBMFile_doc = 
"Convert a DIB (Device Independent Bitmap) to an X-Windows \n"
"bitmap file (XBM format). The XBM file is either returned as\n"
"a string, or written to a file with the name given in the \n"
"third argument.\n"
"Parameters: a handle to a global area containing a DIB,\n"
"    a prefix to be used for the name and an optional filename\n"
"    for file only output.\n";

static PyObject *
DIBToXBMFile(SourceObject *Source, PyObject *args)
{
	int  twRC = TWRC_FAILURE;
	LPBITMAPINFOHEADER lpDib;
	PyObject *rv;
	HANDLE hBitmap;
	int rowBytes;
	int iColours;
	char *szFileName = NULL;
	char *szPrefix = NULL;
	FILE *fp = NULL;
	int iRow, iCol, iByte, iBit, iBitPos;
	char *pBits;
	int iOffset=0;
	int iOutput;
	char szMessage[100];
	char *m, *p;
	char sByte[20];

	if (!PyArg_ParseTuple(args,"ls|si:DIBToXBMFile", &hBitmap, &szPrefix, 
		&szFileName, &iOffset))
		return NULL;

	if ((lpDib = (LPBITMAPINFOHEADER) GlobalLock(hBitmap))==NULL)
	{
        unsigned long lError = GetLastError();
		sprintf(szMessage, "Could Not Lock Bitmap Memory [0x%lx], error %ld", hBitmap, lError);
		PyErr_SetString(excGlobalHeap, szMessage);
		return(NULL);
	}

	// Calculation from MSDN CD.
	rowBytes = (((lpDib->biWidth * lpDib->biBitCount) + 31) & ~31) >> 3;

	// Taken from MSDN
	if (!(iColours = lpDib->biClrUsed))
		if (lpDib->biBitCount != 24)
			iColours = 1 << lpDib->biBitCount;

	if (lpDib->biSizeImage == 0) {
		lpDib->biSizeImage = rowBytes * lpDib->biHeight;
	}

	if (lpDib->biCompression != BI_RGB) {
		sprintf(szMessage, "Cannot handle compressed image. Compression Format %d",
            lpDib->biCompression);
		PyErr_SetString(excImageFormat, szMessage);
	    GlobalUnlock(hBitmap);
		return NULL;
	}

	pBits = &((char*)lpDib)[lpDib->biSize +	(iColours * sizeof(RGBQUAD))];
	if (iOffset)
		pBits = &((char*)lpDib)[iOffset];

	if (szFileName) {
		fp = fopen(szFileName, "wb");
		if (!fp) {
			sprintf(szMessage, "Open Failed: [%.60s]", szFileName);
			PyErr_SetString(excFileError, szMessage);
	        GlobalUnlock(hBitmap);
			return NULL;
		}
		fprintf(fp, "#define %s_width %d\n", szPrefix, lpDib->biWidth);
		fprintf(fp, "#define %s_height %d\n", szPrefix, lpDib->biHeight);
		fprintf(fp, "static char %s_bits[] = {\n", szPrefix);
	} else {
		long lSize;
		long lBits;
		lBits = (lpDib->biWidth * lpDib->biHeight);
		lSize = 200 + (((lBits / (8*12))+1) * 4) + ((lBits / 8) * 6);
		m = malloc(lSize);
		if (!m) {
			sprintf(szMessage, "malloc() Failed: %d bytes", lSize);
			PyErr_SetString(excMemoryError, szMessage);
	        GlobalUnlock(hBitmap);
			return NULL;
		}
		p = m;
		p += sprintf(p, "#define %s_width %d\n", szPrefix, lpDib->biWidth);
		p += sprintf(p, "#define %s_height %d\n", szPrefix, lpDib->biHeight);
		p += sprintf(p, "static char %s_bits[] = {\n", szPrefix);
	}
	iCol = iByte = iBit = iBitPos = 0;
	iOutput=0;
	for (iRow = 0; iRow < lpDib->biHeight; iRow++) {
		for (iCol = 0; iCol < lpDib->biWidth; iCol++) {
			if (iBitPos == 8){
				if (iOutput == 0)  // First Byte			
					sprintf(sByte, "   0x%02.2x", iByte);
				else if (iOutput % 12 == 0)  // First Byte in line
					sprintf(sByte, ",\n   0x%02.2x", iByte);
				else
					sprintf(sByte, ", 0x%02.2x", iByte);
				if (fp)
					fprintf(fp, sByte);
				else
					p += sprintf(p, sByte);
				iBitPos = 0;
				iByte=0;
				iOutput++;
			}
			iBit = iGetDIBBit(pBits, lpDib->biBitCount, lpDib->biWidth, lpDib->biHeight, 
				iRow, iCol);
			iByte |= (iBit << iBitPos);
			iBitPos++;
		}
		if (iBitPos > 0) {
			if (iOutput == 0)  // First Byte			
				sprintf(sByte, "   0x%02.2x", iByte);
			else if (iOutput % 12 == 0)  // First Byte in line
				sprintf(sByte, ",\n   0x%02.2x", iByte);
			else
				sprintf(sByte, ", 0x%02.2x", iByte);
			if (fp)
				fprintf(fp, sByte);
			else
				p += sprintf(p, sByte);
			iBitPos = 0;
			iByte=0;
			iOutput++;
		}
	}
	if (fp) {
		fprintf(fp, "};\n");
		fclose(fp);
		Py_INCREF(Py_None);
		rv = Py_None;
	} else {
		p+=sprintf(p, "};\n");
		rv = Py_BuildValue("z#", m, p-m);
		free(m);
	}
	GlobalUnlock(hBitmap);
	return rv;
}

static char *pVersion_doc = 
"Retrieve the version of the Python Twain Interface \n";

static PyObject *
Version(SourceObject *Source, PyObject *args)
{
	return Py_BuildValue("s", gszVersion);
}

static char *pnew_SourceManager_doc = 
"Constructor for a TWAIN Source Manager Object. This\n"
"constructor has one position argument, HWND, which\n"
"should contain the windows handle of the main window.\n"
"For wxPython users, this can be got using wxWindows.GetHandle()\n"
"\nThe following are the named parameters\n"
" HWND	     mandatory\n"
" MajorNum   default = 1\n"
" MinorNum   default = 0\n"
" Language   default = TWLG_USA\n"
" Country    default = TWCY_USA\n"
" Info       default = 'TWAIN Python Interface 1.0.0.0  10/02/2002'\n"
" ProductName  default = 'TWAIN Python Interface'\n"
" ProtocolMajor default = TWON_PROTOCOLMAJOR\n"
" ProtocolMinor default = TWON_PROTOCOLMINOR\n"
" SupportedGroups default =  DG_IMAGE | DG_CONTROL\n"
" Manufacturer    default =  'Kevin Gill'\n"
" ProductFamily default = 'TWAIN Python Interface'\n";

static PyObject*
new_SourceManager(PyObject* self, PyObject* args, PyObject* kwargs)
{
    SourceManagerObject* SourceManager;
	char          WinDir[WINDIRPATHSIZE];
	TW_STR32      DSMName;
	long          lHwnd;
	TW_UINT16     twRC = TWRC_FAILURE;
	int MajorNum = 1;
	int MinorNum = 0;
	int Language = TWLG_USA;
	int Country  = TWCY_USA;
	char *Info   = "TWAIN Python Interface 1.0.0.0  10/02/2002";
	char *ProductName  = "TWAIN Python Interface";
	int ProtocolMajor = TWON_PROTOCOLMAJOR;
	int ProtocolMinor = TWON_PROTOCOLMINOR;
	int SupportedGroups =  DG_IMAGE | DG_CONTROL;
	char *Manufacturer =  "Kevin Gill";
	char *ProductFamily = "TWAIN Python Interface";
	int i=0;
	int pyErr = 0;
	char szMessage[255];
	
    static char *kwlist[] = {"HWND", "MajorNum", "MinorNum", "Language", "Country", "Info",
		"ProductName", "ProtocolMajor", "ProtocolMinor", "SupportedGroups",
		"Manufacturer", "ProductFamily", NULL}; 

#if TRACE
printf("New SourceManager, thread %d\n", GetCurrentThreadId());
#endif 

    if (!PyArg_ParseTupleAndKeywords(args,kwargs,"l|iiiissiiiss:new_SourceManager", kwlist, 
		&lHwnd,	&MajorNum, &MinorNum, &Language, &Country, &Info,
		&ProductName, &ProtocolMajor, &ProtocolMinor, &SupportedGroups,
		&Manufacturer, &ProductFamily)) 
        return NULL;

    SourceManager = PyObject_New(SourceManagerObject, &SourceManagerType);

	// We need to load the twain source manager. If we fail
	// to load the twain source manager, return an exception.
	// Determine the Path to the DSM DLL
	memset(WinDir, 0, sizeof(char[WINDIRPATHSIZE]));
	memset(DSMName, 0, sizeof(TW_STR32));
	GetWindowsDirectory (WinDir, WINDIRPATHSIZE);
	if (WinDir[strlen(WinDir)-1] != '\\')
		lstrcat(WinDir, "\\");
	lstrcat(WinDir, pDSMNAME);

	SourceManager->hDSMDLL = LoadLibrary(pDSMNAME);
	if (SourceManager->hDSMDLL == NULL || SourceManager->hDSMDLL < (HANDLE)VALID_HANDLE) {
		PyErr_SetString(excSMLoadFileFailed, pDSMNAME);
		PyObject_Del(SourceManager);
		return NULL;
	}

	SourceManager->lpDSM_Entry = (DSMENTRYPROC)GetProcAddress(SourceManager->hDSMDLL, MAKEINTRESOURCE (1));
	if (SourceManager->lpDSM_Entry == NULL) {
		PyErr_SetString(excSMGetProcAddressFailed, pDSMNAME);
		PyObject_Del(SourceManager);
		return NULL;
	}

	// If we reach this point, then there is a source manager.
	SourceManager->state = SM_CLOSED;
	SourceManager->hWnd = (HWND)lHwnd;

	SourceManager->appID.Id = 0; 				// init to 0, but Source Manager will assign real value
	SourceManager->appID.Version.MajorNum = MajorNum;
	SourceManager->appID.Version.MinorNum = MinorNum;
	SourceManager->appID.Version.Language = Language;
	SourceManager->appID.Version.Country  = Country;
	StringCchCopy(SourceManager->appID.Version.Info, sizeof(TW_STR32), Info);
	StringCchCopy(SourceManager->appID.ProductName, sizeof(TW_STR32), ProductName);

	SourceManager->appID.ProtocolMajor = ProtocolMajor;
	SourceManager->appID.ProtocolMinor = ProtocolMinor;
	SourceManager->appID.SupportedGroups =  SupportedGroups;
	StringCchCopy(SourceManager->appID.Manufacturer, sizeof(TW_STR32), Manufacturer);
	StringCchCopy(SourceManager->appID.ProductFamily, sizeof(TW_STR32), ProductFamily);

	//	Create pseudo window for processing messages
	SourceManager->hWndPseudo = CreateWindowInstance(SourceManager->hWnd);
	if (!SourceManager->hWndPseudo) {
		sprintf(szMessage, "Attempt to create pseudo window failed.");
		PyErr_SetString(excInternalError, szMessage);
		kill_SourceManager(SourceManager, TRUE);
		PyObject_Del(SourceManager);
		return NULL;
	}

	twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
		NULL, DG_CONTROL, DAT_PARENT, MSG_OPENDSM,
		(TW_MEMREF)&SourceManager->hWndPseudo,
		sizeof(SourceManager->hWndPseudo), &pyErr, TRUE);
	if (pyErr) return NULL;
	if (twRC != TWRC_SUCCESS) {
		sprintf(szMessage, "[%s], return code %d\n", pDSMNAME, twRC);
		PyErr_SetString(excSMOpenFailed, szMessage);
		kill_SourceManager(SourceManager, TRUE);
		PyObject_Del(SourceManager);
		return NULL;
	}

	SourceManager->state = SM_OPEN;
	SourceManager->threadCallback = NULL;
	SourceManager->pfnCallback = NULL;

	//	TBD - Exception for max reached
	for (i=0; i< MAX_SM_OBJECTS; i++) {
		if (!AllSMObjects[i]) {
			AllSMObjects[i] = SourceManager;
			break;
		}
	}

	SetActiveWindow(SourceManager->hWnd); // Activate the source manager window
    return (PyObject*)SourceManager;
}

static char *pSourceManager_DSM_Entry_doc = 
"This function is used to call the source manager.\n"
"There are four parameters:\n"
"	DataGroup   - DG_*constants\n"
"	DataArgumentType  - DAT_* constants\n"
"	MessageId   - MSG_* constants\n"
"	Data        - python string packed with struct, or a \n"
"	              object from the twainstr module";


static PyObject *
SourceManager_DSM_Entry(SourceManagerObject *SourceManager, PyObject* args)
{
	unsigned short iDataGroup, iDataItemId, iMessageId;
	int iStringLen;
	char *pString;
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	int pyErr = 0;

    if (!PyArg_ParseTuple(args,"hhhz#:SourceManager.DSM_Entry", 
			&iDataGroup, &iDataItemId, &iMessageId, &pString, &iStringLen)) 
	{
#if 0
		//	This work is incomplete. While I think that this section
		//	may be logically correct, it crashes.
		char ptrstr[10];
		PyObject *pParam, *pParamThis;

		if (!PyArg_ParseTuple(args,"hhhO:SourceManager.DSM_Entry", 
				&iDataGroup, &iDataItemId, &iMessageId, &pParam)) 
			return NULL;
		if (!(pParamThis = PyObject_GetAttrString(pParam, "this"))) {
			// TBD Exception
			printf("Object is of invalid form\n");
			return NULL;
		}
		//	TBD - validate result
		PyString_AsStringAndSize(pParamThis, &pString, &iStringLen);
		printf("String [%s], length = %d\n", pString, iStringLen);
		memcpy(ptrstr, &(pString[1]), 8);
		ptrstr[8] = '\0';
		pString = (char *) strtol(ptrstr, NULL, 16);
		iStringLen = -1;
		printf("pString = 0x%lx", (long)pString);
#else
		0;
#endif
	}
	twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
		NULL, iDataGroup, iDataItemId, iMessageId,
		(TW_MEMREF)pString, iStringLen, &pyErr, TRUE);
	if (pyErr) return NULL;

	rv = Py_BuildValue("i", twRC);
	return rv;
}


static char *pSourceManager_ProcessEvent_doc = 
"The TWAIN interface requires that the windows events\n"
"are available to both the application and the twain\n"
"source (which operates in the same process).\n"
"This method is called in the event loop to pass on those\n"
"events.";
static PyObject *
SourceManager_ProcessEvent(SourceManagerObject *SourceManager, PyObject* args)
{
	unsigned short iDataGroup, iDataItemId, iMessageId;
	int iStringLen;
	char *pString;
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	int pyErr = 0;

    if (!PyArg_ParseTuple(args,"hhhz#:SourceManager.ProcessEvent", 
			&iDataGroup, &iDataItemId, &iMessageId, &pString, &iStringLen)) 
        return NULL;

	twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
		NULL, iDataGroup, iDataItemId, iMessageId,
		(TW_MEMREF)pString, iStringLen, &pyErr, TRUE);
	if (pyErr) return NULL;

	rv = Py_BuildValue("i", twRC);
	return rv;
}

static char *pSourceManager_SetCallback_doc = 
"Register a python function to be used for notification that the\n"
"transfer is ready, etc. ";
static PyObject *
SourceManager_SetCallback(SourceManagerObject *SourceManager, PyObject *args)
{
	// This is not the preferred method - better to use WM_COMMAND messages
	// However, I could not work out how to do that with either Tk or Wx

#if TRACE
printf("SetCallback, thread %d\n", GetCurrentThreadId());
#endif 
	
	if (SourceManager->pfnCallback) 
		Py_XDECREF(SourceManager->pfnCallback);  /* Dispose of previous callback */

    if (PyArg_ParseTuple(args, "O:SetCallback", &SourceManager->pfnCallback)) {
        if (!PyCallable_Check(SourceManager->pfnCallback)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }

        Py_XINCREF(SourceManager->pfnCallback);         /* Add a reference to new callback */
		SourceManager->threadCallback = PyThreadState_Get();
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static char *pSourceManager_GetSourceList_doc = 
"Returns a list containing the names of the available source.\n";
static PyObject *
SourceManager_GetSourceList(SourceManagerObject *SourceManager)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	TW_IDENTITY appID;
	int pyErr = 0;

	//	Get the first source
	twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
		NULL, DG_CONTROL, DAT_IDENTITY, MSG_GETFIRST,
		(TW_MEMREF)&appID, sizeof(appID), &pyErr, TRUE);
	if (pyErr) return NULL;

	//	Loop through all the sources
	rv=PyList_New(0);
	while (twRC == TWRC_SUCCESS) {
		PyList_Append(rv, Py_BuildValue("s", appID.ProductName));
		twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
			NULL, DG_CONTROL, DAT_IDENTITY, MSG_GETNEXT,
			(TW_MEMREF)&appID, sizeof(appID), &pyErr, TRUE);
		if (pyErr) return NULL;
	}
	return rv;
}

static char *pSourceManager_OpenSource_doc = 
"Open a TWAIN Source. \n"
"Returns a Source Object, which can be used to communicate with the source\n"
"There is one optional string parameter, which allows the application\n"
"to name the source to be opened, i.e. to open from application configuration\n";
static PyObject *
SourceManager_OpenSource(SourceManagerObject *SourceManager, PyObject* args)
{
	int  twRC = TWRC_FAILURE;
	TW_IDENTITY appID;          // storage for App states
    SourceObject* Source;
	char *szSourceName = "";
	int i;
	int pyErr = 0;
	char szMessage[255];

#if TRACE
printf("OpenSource, thread %d\n", GetCurrentThreadId());
#endif 

    if (!PyArg_ParseTuple(args,"|s:SourceManager.OpenSource", &szSourceName)) 
        return NULL;

	appID.Id = 0;
	if (szSourceName[0]) {
		StringCchCopy(appID.ProductName, sizeof(TW_STR32), szSourceName);
	}
	else {
		// User Select the source
		twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
			NULL, DG_CONTROL, DAT_IDENTITY, MSG_USERSELECT,
			(TW_MEMREF)&appID, sizeof(appID), &pyErr, TRUE);
		if (pyErr) return NULL;

		if (twRC != 0) {
			// None selected by user
			Py_INCREF(Py_None);
			return Py_None;
		}
	}

	// Step 2 - Open the Source
	twRC = CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
		NULL, DG_CONTROL, DAT_IDENTITY, MSG_OPENDS,
		(TW_MEMREF)&appID, sizeof(appID), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS) {
		// Problem Opening the Source - Raise an Exception
		sprintf(szMessage, "return code %d, source[%.40s]",
			twRC, appID.ProductName);
		PyErr_SetString(excDSOpenFailed, szMessage);
		return NULL;
	}

	//	Create the Python Object
    Source = PyObject_New(SourceObject, &SourceType);
	memcpy(&Source->appID, &appID, sizeof(appID));
	Source->pSM = SourceManager;
	Py_INCREF(SourceManager);
	Source->bEnabled = 0;

	//	TBD - Exception for max reached
	for (i=0; i< MAX_SD_OBJECTS; i++) {
		if (!AllSDObjects[i]) {
			AllSDObjects[i] = Source;
			break;
		}
	}

	SetActiveWindow(SourceManager->hWnd); // Activate the application window
    return (PyObject *)Source;
}

static char *pSourceManager_GetIdentity_doc = 
"This function is used to retrieve the identity of our application.\n"
"The information is returned in a dictionary.\n";

static PyObject *
SourceManager_GetIdentity(SourceManagerObject *SourceManager)
{
	TW_IDENTITY *id;
	PyObject *rv;
	int pyErr = 0;

	id = &(SourceManager->appID);

	rv = Py_BuildValue("{s:i,s:i,s:i,s:i,s:s,s:s,s:i,s:i,s:l,s:s,s:s}", 
		"MajorNum", id->Version.MajorNum,
		"MinorNum", id->Version.MinorNum,
		"Language", id->Version.Language,
		"Country", id->Version.Country,
		"Info",  id->Version.Info,
		"ProductName", id->ProductName,
		"ProtocolMajor", id->ProtocolMajor,
		"ProtocolMinor", id->ProtocolMinor,
		"SupportedGroups", id->SupportedGroups,
		"Manufacturer", id->Manufacturer,
		"ProductFamily", id->ProductFamily);
	return(rv);
}

static char *pSourceManager_destroy_doc = 
"This method is used to force the SourceManager to close down.\n"
"It is provided for finer control than letting garbage collection drop the connections.";

static PyObject *
SourceManager_destroy(SourceManagerObject* SourceManager)
{
	kill_SourceManager(SourceManager, TRUE);
	Py_INCREF(Py_None);
    return Py_None;
}


static PyMethodDef SourceManager_methods[] = {
    {"DSM_Entry", (PyCFunction)SourceManager_DSM_Entry, METH_VARARGS, "replaceme"},
    {"ProcessEvent", (PyCFunction)SourceManager_ProcessEvent, METH_VARARGS, "replaceme"},
    {"OpenSource", (PyCFunction)SourceManager_OpenSource, METH_VARARGS, "replaceme"},
    {"GetSourceList", (PyCFunction)SourceManager_GetSourceList, METH_VARARGS, "replaceme"},
    {"SetCallback", (PyCFunction)SourceManager_SetCallback, METH_VARARGS, "replaceme"},
    {"GetIdentity", (PyCFunction)SourceManager_GetIdentity, METH_VARARGS, "replaceme"},
    {"destroy", (PyCFunction)SourceManager_destroy, METH_VARARGS, "replaceme"},
    {NULL, NULL, 0, NULL}
};


static void
kill_SourceManager(SourceManagerObject* SourceManager, boolean bHaveInterp)
{
	//	This method is used to forcably shutdown the SourceManager.
	//	It is called from the destructor, or from the windows process
	//	when a WM_DESTROY message is received. This occurs when the 
	//	program exits without deleting the source manager object.
	
	int i=0;
	HWND hwndPseudo;
	int pyErr = 0;

#if TRACE
printf("kill SourceManager, bHaveInterp = %d, thread %d\n", bHaveInterp, GetCurrentThreadId());
#endif 


	if (SourceManager->hWndPseudo) {
		// A bit of messing with the handles to prevent message propagation
		hwndPseudo = SourceManager->hWndPseudo;
		SourceManager->hWndPseudo = NULL;
		SourceManager->pfnCallback = NULL;
		//SourceManager->hWnd = NULL;

		// Just in case destructor called in wrong order
		for (i=0; i< MAX_SD_OBJECTS; i++) {
			if (AllSDObjects[i] && AllSDObjects[i]->pSM == SourceManager) {
				kill_Source(AllSDObjects[i], bHaveInterp);
				break;
			}
		}

		// This prevents infinite recursion
		for (i=0; i< MAX_SM_OBJECTS; i++) {
			if (AllSMObjects[i] == SourceManager) {
				AllSMObjects[i] = NULL;
				break;
			}
		}

		//	wxWindows fails to exit...
		//	when the object is killed from python, this code works
		//	when it is killed from the window handler, this code
		//	causes problems. The most likely cause is that the latter
		//	scenario involves re-entrancy.
		//  Best option at the moment - FAQ entry.
		if (SourceManager->state == SM_OPEN) {
			//	State 3->State 2
			(void)CallEntryPoint(SourceManager->lpDSM_Entry, &SourceManager->appID,
				NULL, DG_CONTROL, DAT_PARENT, MSG_CLOSEDSM,
				(TW_MEMREF)&hwndPseudo, sizeof(hwndPseudo), &pyErr, bHaveInterp);
		}
		//	State 2->State 1
		FreeLibrary(SourceManager->hDSMDLL);

		DestroyWindowInstance(hwndPseudo);
	}

#if TRACE
printf("kill SourceManager returning\n");
#endif 

}

static void
dealloc_SourceManager(SourceManagerObject* SourceManager)
{
#if TRACE
printf("dealloc SourceManager, thread %d\n", GetCurrentThreadId());
#endif 

	kill_SourceManager(SourceManager, TRUE);
    PyObject_Del(SourceManager);
}

static PyObject *
SourceManager_getattr(SourceManagerObject *self, char *name)
{
	return Py_FindMethod(SourceManager_methods, (PyObject *)self, name);
}


static PyTypeObject SourceManagerType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "SourceManager",
    sizeof(SourceManagerObject),
    0,
    (destructor)dealloc_SourceManager, /*tp_dealloc*/
    0,          /*tp_print*/
    (getattrfunc)SourceManager_getattr,          /*tp_getattr*/
    0,          /*tp_setattr*/
    0,          /*tp_compare*/
    0,          /*tp_repr*/
    0,          /*tp_as_number*/
    0,          /*tp_as_sequence*/
    0,          /*tp_as_mapping*/
    0,          /*tp_hash */
};
//--------------------------------------------------------------
static char *pSource_DSM_Entry_doc = 
"This function is used to call the source via the manager.\n"
"There are four parameters:\n"
"	DataGroup   - int\n"
"	DataArgumentType  - int\n"
"	MessageId   - int\n"
"	Data        - python string packed with struct\n\n"
"	It is the responsibility of the client to marshall\n"
"	the Data value appropriately.\n"
"	The Data item may be modified.\n";


static PyObject *
Source_DSM_Entry(SourceObject *Source, PyObject* args)
{
	unsigned short iDataGroup, iDataItemId, iMessageId;
	int iStringLen;
	char *pString;
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	int pyErr = 0;

    if (!PyArg_ParseTuple(args,"hhhz#:SourceManager.DSM_Entry", 
			&iDataGroup, &iDataItemId, &iMessageId, &pString, &iStringLen)) 
        return NULL;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, iDataGroup, iDataItemId, iMessageId,
		(TW_MEMREF)pString, iStringLen, &pyErr, TRUE);
	if (pyErr) return NULL;

	rv = Py_BuildValue("i", twRC);
	return rv;
}

static LRESULT
Source_ProcessEventImpl(SourceObject *Source, WORD wMsg, DWORD wParam, LONG lParam)
{
	//	Implements the mechanism for the passing events to the data source.
	//	When the data source responds, indicating that there is data ready,
	//	create a command event, and pass it to the application

	//	It is necessary to do this translation, because wxWindows drops 
	//	unrecognised events.

	//	Three command Events, MSG_XFERREADY, MSG_CLOSEDSREQ, MSG_CLOSEDSOK
	int  twRC = TWRC_FAILURE;
	TW_EVENT twEvent;
	MSG msg;
	int pyErr = 0;
	LRESULT lRv = 1L;
    int iThreadSwitched = 0;

#if TRACE
printf("ProcessEventImpl(0x%lx, 0x%x, 0x%lx, 0x%lx), thread %d\n", Source, wMsg, wParam, lParam, GetCurrentThreadId());
#endif 


	if (Source->pSM) {		

		memset(&msg, '\0', sizeof(msg));

		msg.hwnd = Source->pSM->hWndPseudo;
		msg.message = wMsg;
		msg.wParam = wParam;
		msg.lParam = lParam;

		twEvent.pEvent = (TW_MEMREF)&msg;
		twEvent.TWMessage = MSG_NULL;

		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_EVENT, MSG_PROCESSEVENT,
			(TW_MEMREF)&twEvent, sizeof(twEvent), &pyErr, FALSE);

		// Call the default handler before the callback to python. 
		// A problem was occuring where the callback destroyed the 
		// window, and this function crashed.
		lRv = DefWindowProc(Source->pSM->hWndPseudo, wMsg, wParam, lParam); 

		switch (twEvent.TWMessage)
		{
		case MSG_CLOSEDSREQ:
		case MSG_CLOSEDSOK:
		case MSG_XFERREADY:
			// If a callback function has been declared, call it
			// Note that there are re-entrancy risks here.
			if (Source->pSM->pfnCallback) {
				PyObject *pParam, *result;

                // The event callback is called with a single integer
				pParam = Py_BuildValue("(i)", twEvent.TWMessage);

                // Have to switch the interpreter thread - this only works
                // for wxPython and pyGTK.
                // For python 2.3 or later new mechanism for managing GIL
                {
                    PyGILState_STATE state = PyGILState_Ensure();
				    result = PyEval_CallObject(Source->pSM->pfnCallback, pParam);
                    PyGILState_Release(state);
                }

                // Out of date version for python 2.2 and previous.
                //PyEval_RestoreThread(Source->pSM->threadCallback);
				//result = PyEval_CallObject(Source->pSM->pfnCallback, pParam);
                //PyEval_SaveThread();

				Py_DECREF(pParam);
				if (result)
					Py_DECREF(result);
			}
			break;
		case MSG_NULL:
			// no message returned from the source
        default:
            break;
		}
	}

#if TRACE
printf("ProcessEventImpl returning %ld\n", lRv);
#endif 

	return lRv;
}

static PyObject *
Source_GetCapabilityImpl(SourceObject *Source, PyObject* args, TW_UINT16 current)
{
	TW_CAPABILITY twCapability;
	int  twRC = TWRC_FAILURE;
	PyObject *rv, *rv1;
	int iCapability;
	pTW_ONEVALUE pvalOne;
	pTW_ENUMERATION pvalEnumeration;
	pTW_ARRAY pvalArray;
	pTW_RANGE pvalRange;
	char szMessage[100];
	unsigned int iIndex;
	pTW_FIX32 pFixedVal;
	pTW_FRAME pFrame;
	int pyErr = 0;

    if (!PyArg_ParseTuple(args,"i:Source.GetCapability", &iCapability))
        return NULL;

	twCapability.Cap = iCapability;
	twCapability.ConType = TWON_DONTCARE16;
	twCapability.hContainer = NULL;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_CAPABILITY, current,
		(TW_MEMREF)&twCapability, sizeof(twCapability), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC == TWRC_SUCCESS) {
		switch(twCapability.ConType)
		{
		case TWON_ONEVALUE:
			// Single Integer Result
			pvalOne = (pTW_ONEVALUE) GlobalLock(twCapability.hContainer);
			switch (pvalOne->ItemType)
			{
			case TWTY_INT8:
			case TWTY_UINT8:
				rv = Py_BuildValue("(i,i)", pvalOne->ItemType, pvalOne->Item &0xFF);
				break;
			case TWTY_INT16:
			case TWTY_UINT16:
			case TWTY_BOOL:
				rv = Py_BuildValue("(i,i)", pvalOne->ItemType, pvalOne->Item &0xFFFF);
				break;
			case TWTY_UINT32:
			case TWTY_INT32:
				rv = Py_BuildValue("(i,l)", pvalOne->ItemType, pvalOne->Item);
				break;
			case TWTY_FIX32:
				rv = Py_BuildValue("(i,f)", pvalOne->ItemType, Fix32ToFloat((pTW_FIX32)&(pvalOne->Item)));
				break;
			case TWTY_FRAME:
				pFrame = (pTW_FRAME)&(pvalOne->Item);
				{
					double d1, d2, d3, d4;
					d1 = Fix32ToFloat(&pFrame->Left);
					d2 = Fix32ToFloat(&pFrame->Top);
					d3 = Fix32ToFloat(&pFrame->Right);
					d4 = Fix32ToFloat(&pFrame->Bottom);
					rv = Py_BuildValue("(i, (f, f, f, f))", pvalOne->ItemType, d1, d2, d3, d4);
				}
				break;
			default:
				sprintf(szMessage, "Capability Code = %d, Format Code = %d, Item Type = %d", 
					iCapability, twCapability.ConType, pvalOne->ItemType);
				PyErr_SetString(excCapabilityFormatNotSupported, szMessage);
				rv = NULL;
			}
			//free hContainer allocated by Source
			GlobalFree((HANDLE)twCapability.hContainer);
			return rv;
		case TWON_RANGE:
			// Value can be within a range
			pvalRange = (pTW_RANGE) GlobalLock(twCapability.hContainer);
			rv = Py_BuildValue("{s:l, s:l, s:l, s:l, s:l}", 
				"MinValue", pvalRange->MinValue, "MaxValue", pvalRange->MaxValue,
				"StepSize", pvalRange->StepSize, "DefaultValue", pvalRange->DefaultValue,
				"CurrentValue", pvalRange->CurrentValue);
			//free hContainer allocated by Source
			GlobalFree((HANDLE)twCapability.hContainer);
			return rv;
		case TWON_ENUMERATION:
			/* TWON_ENUMERATION. Container for a collection of values. */
			pvalEnumeration = (pTW_ENUMERATION) GlobalLock(twCapability.hContainer);
			rv1=PyList_New(0);
			for (iIndex=0; iIndex<pvalEnumeration->NumItems; iIndex++) {
				char *ptr = (char *)&(pvalEnumeration->ItemList[0]);
				switch (pvalEnumeration->ItemType)
				{
				case TWTY_INT8:
				case TWTY_UINT8:
					PyList_Append(rv1, Py_BuildValue("i", ((char *)ptr)[iIndex] & 0xFF));
					break;
				case TWTY_INT16:
				case TWTY_UINT16:
				case TWTY_BOOL:
					PyList_Append(rv1, Py_BuildValue("i", ((unsigned short *)ptr)[iIndex] & 0xFFFF));
					break;
				case TWTY_UINT32:
				case TWTY_INT32:
					PyList_Append(rv1, Py_BuildValue("l", ((unsigned long *)ptr)[iIndex]));
					break;
				case TWTY_FIX32:
					pFixedVal = (pTW_FIX32)&(ptr)[iIndex];
					PyList_Append(rv1, Py_BuildValue("f", Fix32ToFloat(pFixedVal)));
					break;
				case TWTY_STR32:
					if (memchr(ptr + (sizeof(TW_STR32) * iIndex), '\0', 32))
						PyList_Append(rv1, Py_BuildValue("s", ptr + (sizeof(TW_STR32) * iIndex)));
					else
						PyList_Append(rv1, Py_BuildValue("s#", ptr + (sizeof(TW_STR32) * iIndex), 32));
					break;
				case TWTY_STR64:
					if (memchr(ptr + (sizeof(TW_STR64) * iIndex), '\0', 64))
						PyList_Append(rv1, Py_BuildValue("s", ptr + (sizeof(TW_STR64) * iIndex)));
					else
						PyList_Append(rv1, Py_BuildValue("s#", ptr + (sizeof(TW_STR64) * iIndex), 64));
					break;
				case TWTY_STR128:
					if (memchr(ptr + (sizeof(TW_STR128) * iIndex), '\0', 128))
						PyList_Append(rv1, Py_BuildValue("s", ptr + (sizeof(TW_STR128) * iIndex)));
					else
						PyList_Append(rv1, Py_BuildValue("s#", ptr + (sizeof(TW_STR128) * iIndex), 128));
					break;
				case TWTY_STR255:
					if (memchr(ptr + (sizeof(TW_STR255) * iIndex), '\0', 255))
						PyList_Append(rv1, Py_BuildValue("s", ptr + (sizeof(TW_STR255) * iIndex)));
					else
						PyList_Append(rv1, Py_BuildValue("s#", ptr + (sizeof(TW_STR255) * iIndex), 255));
					break;

				default:
					sprintf(szMessage, "Capability Code = %d, Format Code = %d, Item Type = %d", 
						iCapability, twCapability.ConType, pvalEnumeration->ItemType);
					PyErr_SetString(excCapabilityFormatNotSupported, szMessage);
					rv = NULL;
				}
			}

			rv = Py_BuildValue("(i, (l, l, O))", pvalEnumeration->ItemType, 
				pvalEnumeration->CurrentIndex,
				pvalEnumeration->DefaultIndex, rv1);
			GlobalFree((HANDLE)twCapability.hContainer);
			return rv;
		case TWON_ARRAY:
			/* TWON_ARRAY. Container for array of values (a simplified TW_ENUMERATION) */
			pvalArray = (pTW_ARRAY) GlobalLock(twCapability.hContainer);
			rv1=PyList_New(0);
			for (iIndex=0; iIndex<pvalArray->NumItems; iIndex++) {
				switch (pvalArray->ItemType)
				{
				case TWTY_INT8:
				case TWTY_UINT8:
					PyList_Append(rv1, Py_BuildValue("i", ((char *)pvalArray->ItemList)[iIndex] & 0xFF));
					break;
				case TWTY_INT16:
				case TWTY_UINT16:
				case TWTY_BOOL:
					PyList_Append(rv1, Py_BuildValue("i", ((unsigned *)pvalArray->ItemList)[iIndex] & 0xFFFF));
					break;
				case TWTY_UINT32:
				case TWTY_INT32:
					PyList_Append(rv1, Py_BuildValue("l", ((unsigned long *)pvalArray->ItemList)[iIndex]));
					break;
				default:
					sprintf(szMessage, "Capability Code = %d, Format Code = %d, Item Type = %d", 
						iCapability, twCapability.ConType, pvalArray->ItemType);
					PyErr_SetString(excCapabilityFormatNotSupported, szMessage);
					rv1 = NULL;
				}
			}
			rv = Py_BuildValue("(i, O)", pvalArray->ItemType, rv1);
			GlobalFree((HANDLE)twCapability.hContainer);
			return rv;
		default:
			sprintf(szMessage, "Capability Code = %d, Format Code = %d", 
				iCapability, twCapability.ConType);
			PyErr_SetString(excCapabilityFormatNotSupported, szMessage);
		}
	} else {
		return Source_MapTWCCToException(Source, NULL);
	}
	Py_INCREF(Py_None);
    return Py_None;
}

//	This function is an internal helper function only. It
//	getst he status code from the source, and sets up an
//	exception object
static PyObject *
Source_MapTWCCToException(SourceObject *Source, char *szValue)
{
	int  twRC = TWRC_FAILURE;
	TW_STATUS twStatus;
	PyObject *excClass;
	char szMessageExtra[1024];
	char *pMsg;
	int pyErr = 0;

	szMessageExtra[0] = '\0';

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_STATUS, MSG_GET,
		(TW_MEMREF)&twStatus, sizeof(twStatus), &pyErr, TRUE);

	switch (twStatus.ConditionCode) 
	{
	case TWCC_SUCCESS:			excClass = excTWCC_SUCCESS; break;
	case TWCC_BUMMER:			excClass = excTWCC_BUMMER; break;
	case TWCC_LOWMEMORY:		excClass = excTWCC_LOWMEMORY; break;
	case TWCC_NODS:				excClass = excTWCC_NODS; break;
	case TWCC_OPERATIONERROR:	excClass = excTWCC_OPERATIONERROR; break;
	case TWCC_BADCAP:			excClass = excTWCC_BADCAP; break;
	case TWCC_BADPROTOCOL:		excClass = excTWCC_BADPROTOCOL; break;
	case TWCC_BADVALUE:			excClass = excTWCC_BADVALUE; break;
	case TWCC_SEQERROR:			excClass = excTWCC_SEQERROR; break;
	case TWCC_BADDEST:			excClass = excTWCC_BADDEST; break;
	case TWCC_CAPUNSUPPORTED:	excClass = excTWCC_CAPUNSUPPORTED; break;
	case TWCC_CAPBADOPERATION:	excClass = excTWCC_CAPBADOPERATION; break;
	case TWCC_CAPSEQERROR:		excClass = excTWCC_CAPSEQERROR; break;
	case TWCC_DENIED:			excClass = excTWCC_DENIED; break;
	case TWCC_FILEEXISTS:		excClass = excTWCC_FILEEXISTS; break;
	case TWCC_FILENOTFOUND:		excClass = excTWCC_FILENOTFOUND; break;
	case TWCC_NOTEMPTY:			excClass = excTWCC_NOTEMPTY; break;
	case TWCC_PAPERJAM:			excClass = excTWCC_PAPERJAM; break;
	case TWCC_PAPERDOUBLEFEED:	excClass = excTWCC_PAPERDOUBLEFEED; break;
	case TWCC_FILEWRITEERROR:	excClass = excTWCC_FILEWRITEERROR; break;
	case TWCC_CHECKDEVICEONLINE:excClass = excTWCC_CHECKDEVICEONLINE; break;
	default:
		excClass = excTWCC_UNKNOWN;
		if (szValue)
			sprintf(szMessageExtra, "ConditionCode = %d: %s",twStatus.ConditionCode,
				szValue);
		else
			sprintf(szMessageExtra, "ConditionCode = %d",twStatus.ConditionCode);
	}

	if (szMessageExtra[0])
		pMsg = &(szMessageExtra[0]);
	else
		pMsg = szValue;

	if (pMsg) {
		PyErr_SetString(excClass, pMsg);
	}
	else {
		PyErr_SetNone(excClass);
	}
	return NULL;
}




static char *pSource_GetCapability_doc =
"This function is used to return the capabililty information from the source.\n"
"If the capability is not supported, an exception should be returned.\n"
"Capabilities are returned as a tuple of a type (TWTY_*) and a value.\n"
"The format of values depends on their container type.\n"
"Capabilities can be in any of the following containers:\n"
"	singleton, range, enumerator or array.\n"
"\n singletons are returned as a single value (integer or string)\n"
" ranges are returned as a tuple dictionary containing MinValue,\n"
"     MaxValue, StepSize, DefaultValue and CurrentValue\n"
" enumerators and arrays are returned as tuples, each containing\n"
"     a list which has the actual values";
static PyObject *
Source_GetCapability(SourceObject *Source, PyObject* args)
{
	return Source_GetCapabilityImpl(Source, args, MSG_GET);
}

static char *pSource_GetCapabilityCurrent_doc =
"This function is used to return the current value of a capabililty from the source.\n"
"If the capability is not supported, an exception should be returned.\n"
"Capabilities are returned as a tuple of a type (TWTY_*) and a value.\n"
"The format of values depends on their container type.\n"
"Capabilities can be in any of the following containers:\n"
"	singleton, range, enumerator or array.\n"
"\n singletons are returned as a single value (integer or string)\n"
" ranges are returned as a tuple dictionary containing MinValue,\n"
"     MaxValue, StepSize, DefaultValue and CurrentValue\n"
" enumerators and arrays are returned as tuples, each containing\n"
"     a list which has the actual values";
static PyObject *
Source_GetCapabilityCurrent(SourceObject *Source, PyObject* args)
{
	return Source_GetCapabilityImpl(Source, args, MSG_GETCURRENT);
}

static char *pSource_GetCapabilityDefault_doc =
"This function is used to return the default value of a capabililty from the source.\n"
"If the capability is not supported, an exception should be returned.\n"
"Capabilities are returned as a tuple of a type (TWTY_*) and a value.\n"
"The format of values depends on their container type.\n"
"Capabilities can be in any of the following containers:\n"
"	singleton, range, enumerator or array.\n"
"\n singletons are returned as a single value (integer or string)\n"
" ranges are returned as a tuple dictionary containing MinValue,\n"
"     MaxValue, StepSize, DefaultValue and CurrentValue\n"
" enumerators and arrays are returned as tuples, each containing\n"
"     a list which has the actual values";
static PyObject *
Source_GetCapabilityDefault(SourceObject *Source, PyObject* args)
{
	return Source_GetCapabilityImpl(Source, args, MSG_GETDEFAULT);
}


static char *pSource_SetCapability_doc =
"This function is used to set the value of a capablilty in the source.\n"
"Three parameters are required, a Capability Identifier (twain.CAP_* or \n"
"twain.ICAP_*) a value type (twain.TWTY_*) and a value\n"
"If the capability is not supported, an exception should be returned.\n"
"This function is used to set a value using a TW_ONEVALUE.\n";
static PyObject *
Source_SetCapability(SourceObject *Source, PyObject* args)
{
	TW_CAPABILITY twCapability;
	int  twRC = TWRC_FAILURE;
	PyObject *rv, *pParam;
	int iCapability;
	unsigned long lValue;
	TW_STR255 szValue;
	TW_FIX32 fixValue;
	TW_FRAME frameValue;
	pTW_ONEVALUE pval;
	char szMessage[255];
	int iTwainType;
	int pyErr = 0;

	if (!PyArg_ParseTuple(args,"iiO:Source.SetCapability", &iCapability, 
		&iTwainType, &pParam))
		return NULL;

	switch (iTwainType)
	{
	case TWTY_INT8:
	case TWTY_INT16:
	case TWTY_INT32:
	case TWTY_UINT8:
	case TWTY_UINT16:
	case TWTY_UINT32:
	case TWTY_BOOL:
		// Check that the value is a Long or an Integer
		if (PyLong_Check(pParam)) {
			lValue = PyLong_AsLong(pParam);
		}
		else if (PyInt_Check(pParam)) {
			lValue = PyInt_AsLong(pParam);
		}
		else {
			PyErr_SetString(excParamError, 
				"Parameter Error, TWTY_BOOL is not an int");
			return NULL;
		}
		break;
	case TWTY_STR32:
	case TWTY_STR64:
	case TWTY_STR128:
	case TWTY_STR255:
		if (PyString_Check(pParam)) {
			strncpy(szValue, PyString_AsString(pParam), 255);
			szValue[254] = '\0';
		}
		else {
			PyErr_SetString(excParamError, 
				"Parameter Error, TWTY_STR?? is not a string");
			return NULL;
		}
		break;
	case TWTY_FIX32:
		/* Fixed point structure type. - Expect Floating Point from Python*/
		if (PyFloat_Check(pParam)) {
			fixValue = FloatToFix32(PyFloat_AsDouble(pParam));
		}
		else {
			PyErr_SetString(excParamError, 
				"Parameter Error, TWTY_FIX32 is not a float");
			return NULL;
		}
		break;
	case TWTY_FRAME:
		// Object should be a four part tuple
		if (PyTuple_Check(pParam) && PyTuple_Size(pParam) == 4) {
			frameValue.Left = FloatToFix32(PyFloat_AsDouble(PyTuple_GET_ITEM(pParam, 0)));
			frameValue.Top = FloatToFix32(PyFloat_AsDouble(PyTuple_GET_ITEM(pParam, 1)));
			frameValue.Right = FloatToFix32(PyFloat_AsDouble(PyTuple_GET_ITEM(pParam, 2)));
			frameValue.Bottom = FloatToFix32(PyFloat_AsDouble(PyTuple_GET_ITEM(pParam, 3)));
		}
		else {
			PyErr_SetString(excParamError, 
				"Parameter Error, TWTY_FRAME is not a tuple (4 member)");
			return NULL;
		}
		break;
	
	default:
		sprintf(szMessage, "Capability Code = %d, Format Code = %d", 
				iCapability, iTwainType);
		PyErr_SetString(excCapabilityFormatNotSupported, szMessage);
		return NULL;
	}		
		
	twCapability.hContainer = GlobalAlloc(GHND, sizeof(TW_ONEVALUE) + sizeof(TW_STR255));
	pval = (pTW_ONEVALUE) GlobalLock(twCapability.hContainer);
	pval->ItemType = iTwainType;
	switch (iTwainType)
	{
	case TWTY_INT8:
	case TWTY_BOOL:
	case TWTY_INT16:
	case TWTY_INT32:
	case TWTY_UINT8:
	case TWTY_UINT16:
	case TWTY_UINT32:
			pval->Item = lValue;
			break;
	case TWTY_STR32:
	case TWTY_STR64:
	case TWTY_STR128:
	case TWTY_STR255:
		strcpy((char *)&pval->Item, szValue);
		break;
	case TWTY_FIX32:
		memcpy((char *)&pval->Item, &fixValue, sizeof(fixValue));
		break;
	case TWTY_FRAME:
		memcpy((char *)&pval->Item, &frameValue, sizeof(frameValue));
		break;
	}
	GlobalUnlock(twCapability.hContainer);

	twCapability.Cap = iCapability;
	twCapability.ConType = TWON_ONEVALUE;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_CAPABILITY, MSG_SET,
		(TW_MEMREF)&twCapability, sizeof(twCapability), &pyErr, TRUE);
	if (pyErr) return NULL;

	GlobalFree((HANDLE)twCapability.hContainer);

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	rv = Py_BuildValue("i", twRC);
	return rv;
}

static char *pSource_ResetCapability_doc =
"This function is used to reset the value of a capablilty to the source default.\n"
"One parameter is required, a Capability Identifier (twain.CAP_* or \n"
"twain.ICAP_*).";
static PyObject *
Source_ResetCapability(SourceObject *Source, PyObject* args)
{
	TW_CAPABILITY twCapability;
	int  twRC = TWRC_FAILURE;
	int iCapability;
	int pyErr = 0;

	if (!PyArg_ParseTuple(args,"i:Source.SetCapability", &iCapability))
		return NULL;

	twCapability.Cap = iCapability;
	twCapability.ConType = TWON_DONTCARE16;
	twCapability.hContainer = NULL;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_CAPABILITY, MSG_RESET,
		(TW_MEMREF)&twCapability, sizeof(twCapability), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	Py_INCREF(Py_None);
    return Py_None;
}


static char *pSource_RequestAcquire_doc = 
"This function is used to ask the source to begin aquisition.\n"
"Parameters:\n"
"	ShowUI - bool (default 1)\n"
"	ModalUI - bool (default 1)\n";

static PyObject *
Source_RequestAcquire(SourceObject *Source, PyObject* args)
{
	int  twRC = TWRC_FAILURE;
	int iShowUI = 1;
	int iShowModal = 1;
	int pyErr = 0;

#if TRACE
printf("RequestAcquire, thread %d\n", GetCurrentThreadId());
#endif 

	if (!PyArg_ParseTuple(args,"|ii:SourceManager.RequestAcquire", 
		&iShowUI, &iShowModal)) 
       return NULL;

	Source->twUI.ShowUI=iShowUI;
	Source->twUI.ModalUI=iShowModal;
	Source->twUI.hParent = Source->pSM->hWnd;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_USERINTERFACE, MSG_ENABLEDS,
		(TW_MEMREF)&Source->twUI, sizeof(Source->twUI), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);
	
	Source->bEnabled = 1;

	Py_INCREF(Py_None);
    return Py_None;
}

static char *pSource_HideUI_doc = 
"This function is used to ask the source to hide the user interface.\n";

static PyObject *
Source_HideUI(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	int pyErr = 0;

#if TRACE
printf("HideUI, thread %d\n", GetCurrentThreadId());
#endif 

	if (Source->bEnabled) {
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_USERINTERFACE, MSG_DISABLEDS,
			(TW_MEMREF)&Source->twUI, sizeof(Source->twUI), &pyErr, TRUE);
		if (pyErr) return NULL;

		if (twRC != TWRC_SUCCESS) 
			return Source_MapTWCCToException(Source, NULL);
		
		Source->bEnabled = 0;
	}
	Py_INCREF(Py_None);
    return Py_None;
}


static char *pSource_GetImageInfo_doc = 
"This function is used to ask the source for Image Info.\n"
"Normally, the application is notified that the image is \n"
"ready for transfer using the message loop. However, it is\n"
"hard to get at the message loop in toolkits such as wxPython.\n"
"As an alternative, I poll the source looking for image information.\n"
"When the image information is available, the image is ready for transfer\n";

static PyObject *
Source_GetImageInfo(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv, *rv1;
	TW_IMAGEINFO twImageInfo;
	int pyErr = 0;

#if TRACE
printf("GetImageInfo, thread %d\n", GetCurrentThreadId());
#endif 

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_IMAGE, DAT_IMAGEINFO, MSG_GET,
		(TW_MEMREF)&twImageInfo, sizeof(twImageInfo), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	rv1 = Py_BuildValue("[i,i,i,i,i,i,i,i]", 
		twImageInfo.BitsPerSample[0],
		twImageInfo.BitsPerSample[1],
		twImageInfo.BitsPerSample[2],
		twImageInfo.BitsPerSample[3],
		twImageInfo.BitsPerSample[4],
		twImageInfo.BitsPerSample[5],
		twImageInfo.BitsPerSample[6],
		twImageInfo.BitsPerSample[7]);
	
	rv = Py_BuildValue("{s:l,s:l,s:l,s:l,s:i,s:O,s:i,s:i,s:i,s:l}", 
		"XResolution", twImageInfo.XResolution,
		"YResolution", twImageInfo.YResolution,
		"ImageWidth", twImageInfo.ImageWidth,
		"ImageLength", twImageInfo.ImageLength,
		"SamplesPerPixel", twImageInfo.SamplesPerPixel,
		"BitsPerSample", rv1,
		"BitsPerPixel", twImageInfo.BitsPerPixel,
		"Planar", twImageInfo.Planar,
		"PixelType", twImageInfo.PixelType,
		"Compression", twImageInfo.Compression
		);
	Py_DECREF(rv1); // rv created its own reference to it
	return rv;
}

static char *pSource_GetImageLayout_doc = 
"This function is used to ask the source for Image Layout.\n"
"It returns a tuple containing frame coordinates, document\n"
"number, page number, frame number.\n";

static PyObject *
Source_GetImageLayout(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv, *rv1;
	TW_IMAGELAYOUT twImageLayout;
	int pyErr = 0;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_IMAGE, DAT_IMAGELAYOUT, MSG_GET,
		(TW_MEMREF)&twImageLayout, sizeof(twImageLayout), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	rv1 = Py_BuildValue("(d,d,d,d)", 
		Fix32ToFloat(&twImageLayout.Frame.Left),
		Fix32ToFloat(&twImageLayout.Frame.Top),
		Fix32ToFloat(&twImageLayout.Frame.Right),
		Fix32ToFloat(&twImageLayout.Frame.Bottom));
	
	rv = Py_BuildValue("(O, l, l, l)", rv1,
		twImageLayout.DocumentNumber, twImageLayout.PageNumber,
		twImageLayout.FrameNumber);

	Py_DECREF(rv1); // rv created its own reference to it
	return rv;
}

static char *pSource_SetImageLayout_doc = 
"This function is used to inform the source of the Image Layout.\n"
"It uses a tuple containing frame coordinates, document\n"
"number, page number, frame number.\n";

static PyObject *
Source_SetImageLayout(SourceObject *Source, PyObject* args)
{
	int  twRC = TWRC_FAILURE;
	TW_IMAGELAYOUT twImageLayout;
	double dTop, dLeft, dRight, dBottom;
	int pyErr = 0;

	if (!PyArg_ParseTuple(args,"(dddd)lll:Source.SetImageLayout", 
		&dLeft, &dTop, &dRight, &dBottom, &twImageLayout.DocumentNumber, 
		&twImageLayout.PageNumber, &twImageLayout.FrameNumber))
		return NULL;

	twImageLayout.Frame.Top = FloatToFix32(dTop);
	twImageLayout.Frame.Left = FloatToFix32(dLeft);
	twImageLayout.Frame.Bottom = FloatToFix32(dBottom);
	twImageLayout.Frame.Right = FloatToFix32(dRight);

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_IMAGE, DAT_IMAGELAYOUT, MSG_SET,
		(TW_MEMREF)&twImageLayout, sizeof(twImageLayout), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	Py_INCREF(Py_None);
    return Py_None;
}

static char *pSource_XferImageNatively_doc = 
"Perform a 'Native' form transfer of the image. \n"
"When successful, this routine returns two values, \n"
"an image handle and a count of the number of images \n"
"remaining in the source.\n";

static PyObject *
Source_XferImageNatively(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	HANDLE hBitmap;   // Handle to the bitmap
	TW_BOOL PendingXfers = TRUE;
	int iXFersDone=0;
	TW_PENDINGXFERS twPendingXFers;
	int pyErr = 0;

#if TRACE
printf("XferImageNatively, thread %d\n", GetCurrentThreadId());
#endif 


	hBitmap = 0;
	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_IMAGE, DAT_IMAGENATIVEXFER, MSG_GET,
		(TW_MEMREF)&hBitmap, sizeof(hBitmap), &pyErr, TRUE);
	if (pyErr) return NULL;

	// Check the return code
	switch (twRC)
	{
	case TWRC_XFERDONE:
		// Acknowledge the end of the transfer
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
		if (pyErr) return NULL;

		rv = Py_BuildValue("(l, l)", (long)hBitmap, twPendingXFers.Count);
		return rv;
	case TWRC_CANCEL:
		// Acknowledge the end of the transfer
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
		if (pyErr) return NULL;

		PyErr_SetNone(excDSTransferCancelled);
		return NULL;
	case TWRC_FAILURE:
	default:
		return Source_MapTWCCToException(Source, NULL);
	}
}



static char *pSource_GetSourceName_doc = 
"Get the name of the source. This can be used later for\n"
"connecting to the same source. \n";

static PyObject *
Source_GetSourceName(SourceObject *Source)
{
	return Py_BuildValue("s", Source->appID.ProductName);
}

static char *pSource_GetXferFileName_doc = 
"Retrieve the configured transfer file name / format\n";

static PyObject *
Source_GetXferFileName(SourceObject *Source)
{
	PyObject *rv;
	TW_SETUPFILEXFER twSetupFileXfer;
	int  twRC = TWRC_FAILURE;
	int pyErr = 0;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_SETUPFILEXFER, MSG_GET,
		(TW_MEMREF)&twSetupFileXfer, sizeof(twSetupFileXfer), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	rv = Py_BuildValue("(s, i)", twSetupFileXfer.FileName,
		twSetupFileXfer.Format);
	return rv;
}


static char *pSource_SetXferFileName_doc = 
"Where the application is transferring the data via a file,\n"
"configure the file name. \n";

static PyObject *
Source_SetXferFileName(SourceObject *Source, PyObject *args)
{
	char *szFileName;
	int iFormat = -1;
	TW_SETUPFILEXFER twSetupFileXfer;
	int  twRC = TWRC_FAILURE;
	int pyErr = 0;

	if (!PyArg_ParseTuple(args,"s|i:Source.SetXferFileName", &szFileName, &iFormat))
		return NULL;

	if (iFormat != -1)
		twSetupFileXfer.Format = iFormat;
	else {
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_SETUPFILEXFER, MSG_GET,
			(TW_MEMREF)&twSetupFileXfer, sizeof(twSetupFileXfer), &pyErr, TRUE);
		if (pyErr) return NULL;
	}

	StringCchCopy(twSetupFileXfer.FileName,
        sizeof(twSetupFileXfer.FileName), szFileName);

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_SETUPFILEXFER, MSG_SET,
		(TW_MEMREF)&twSetupFileXfer, sizeof(twSetupFileXfer), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	Py_INCREF(Py_None);
    return Py_None;
}

static char *pSource_XferImageByFile_doc = 
"Perform a file based transfer of the image. \n"
"When successful, the file is saved to the image file, \n"
"defined in a previous calle to SetXferFileName.\n"
"Returns  the number of pending transfers\n";

static PyObject *
Source_XferImageByFile(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	TW_BOOL PendingXfers = TRUE;
	int iXFersDone=0;
	TW_PENDINGXFERS twPendingXFers;
	int pyErr = 0;

	// Transfer the image by file 
	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_IMAGE, DAT_IMAGEFILEXFER, MSG_GET,
		(TW_MEMREF)NULL, 0, &pyErr, TRUE);
	if (pyErr) return NULL;

	// Check the return code
	switch (twRC)
	{
	case TWRC_XFERDONE:
		// Acknowledge the end of the transfer
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
		if (pyErr) return NULL;
		rv = Py_BuildValue("i", twPendingXFers.Count);
		return rv;
	case TWRC_CANCEL:
		// Acknowledge the end of the transfer
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
		if (pyErr) return NULL;
		PyErr_SetNone(excDSTransferCancelled);
		return NULL;
	default:
		return Source_MapTWCCToException(Source, NULL);
	}
}

static char *pSource_XferAudioByFile_doc = 
"Perform a file based transfer of the audio. \n"
"When successful, the file is saved to the audio file, \n"
"defined in a previous calle to SetXferFileName.\n"
"Returns  the number of pending transfers\n";

static PyObject *
Source_XferAudioByFile(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	TW_BOOL PendingXfers = TRUE;
	int iXFersDone=0;
	TW_PENDINGXFERS twPendingXFers;
	int pyErr = 0;

	// Transfer the audio by file 
	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_AUDIO, DAT_AUDIOFILEXFER, MSG_GET,
		(TW_MEMREF)NULL, 0, &pyErr, TRUE);
	if (pyErr) return NULL;

	// Check the return code
	switch (twRC)
	{
	case TWRC_XFERDONE:
		// Acknowledge the end of the transfer
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
		if (pyErr) return NULL;
		rv = Py_BuildValue("i", twPendingXFers.Count);
		return rv;
	case TWRC_CANCEL:
		// Acknowledge the end of the transfer
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
		if (pyErr) return NULL;
		PyErr_SetNone(excDSTransferCancelled);
		return NULL;
	default:
		return Source_MapTWCCToException(Source, NULL);
	}
}




static char *pSource_CancelOnePendingXfer_doc = 
"Cancel one pending transfer on the data source.\n"
"Returns the number still remaining in the data source\n.";

static PyObject *
Source_CancelOnePendingXfer(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	PyObject *rv;
	TW_PENDINGXFERS twPendingXFers;
	int pyErr = 0;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER,
		(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	rv = Py_BuildValue("i", twPendingXFers.Count);
	return rv;
}

static char *pSource_CancelAllPendingXfers_doc = 
"Cancel all outstanding transfers on the data source.\n";

static PyObject *
Source_CancelAllPendingXfers(SourceObject *Source)
{
	int  twRC = TWRC_FAILURE;
	TW_PENDINGXFERS twPendingXFers;
	int pyErr = 0;

	twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
		&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_RESET,
		(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, TRUE);
	if (pyErr) return NULL;

	if (twRC != TWRC_SUCCESS)
		return Source_MapTWCCToException(Source, NULL);

	Py_INCREF(Py_None);
    return Py_None;
}



static char *pSource_GetIdentity_doc = 
"This function is used to retrieve information about the source.\n"
"driver. The information is returned in a dictionary.\n";

static PyObject *
Source_GetIdentity(SourceObject *Source)
{
	TW_IDENTITY *id;
	PyObject *rv;

	id = &(Source->appID);

	rv = Py_BuildValue("{s:i,s:i,s:i,s:i,s:s,s:s,s:i,s:i,s:l,s:s,s:s}", 
		"MajorNum", id->Version.MajorNum,
		"MinorNum", id->Version.MinorNum,
		"Language", id->Version.Language,
		"Country", id->Version.Country,
		"Info",  id->Version.Info,
		"ProductName", id->ProductName,
		"ProtocolMajor", id->ProtocolMajor,
		"ProtocolMinor", id->ProtocolMinor,
		"SupportedGroups", id->SupportedGroups,
		"Manufacturer", id->Manufacturer,
		"ProductFamily", id->ProductFamily);
	return(rv);
}


static char *pSource_destroy_doc = 
"This method is used to distroy the data source object.\n"
"It gives finer control over this connects than relying on garbage collection.\n";

static PyObject *
Source_destroy(SourceObject* Source)
{
	kill_Source(Source, TRUE);
	Py_INCREF(Py_None);
    return Py_None;
}


static PyMethodDef Source_methods[] = {
    {"DSM_Entry", (PyCFunction)Source_DSM_Entry, METH_VARARGS, "replaceme"},
    {"RequestAcquire", (PyCFunction)Source_RequestAcquire, METH_VARARGS, "replaceme"},
    {"GetCapability", (PyCFunction)Source_GetCapability, METH_VARARGS, "replaceme"},
    {"SetCapability", (PyCFunction)Source_SetCapability, METH_VARARGS, "replaceme"},
    {"GetImageInfo", (PyCFunction)Source_GetImageInfo, METH_VARARGS, "replaceme"},
    {"XferImageNatively", (PyCFunction)Source_XferImageNatively, METH_VARARGS, "replaceme"},
    {"GetCapabilityCurrent", (PyCFunction)Source_GetCapabilityCurrent, METH_VARARGS, "replaceme"},
    {"GetCapabilityDefault", (PyCFunction)Source_GetCapabilityDefault, METH_VARARGS, "replaceme"},
    {"ResetCapability", (PyCFunction)Source_ResetCapability, METH_VARARGS, "replaceme"},
    {"GetImageLayout", (PyCFunction)Source_GetImageLayout, METH_VARARGS, "replaceme"},
    {"SetImageLayout", (PyCFunction)Source_SetImageLayout, METH_VARARGS, "replaceme"},
    {"GetSourceName", (PyCFunction)Source_GetSourceName, METH_NOARGS, "replaceme"},
    {"XferImageByFile", (PyCFunction)Source_XferImageByFile, METH_NOARGS, "replaceme"},
    {"SetXferFileName", (PyCFunction)Source_SetXferFileName, METH_VARARGS, "replaceme"},
    {"GetIdentity", (PyCFunction)Source_GetIdentity, METH_NOARGS, "replaceme"},
    {"CancelOnePendingXfer", (PyCFunction)Source_CancelOnePendingXfer, METH_NOARGS, "replaceme"},
    {"CancelAllPendingXfers", (PyCFunction)Source_CancelAllPendingXfers, METH_NOARGS, "replaceme"},
    {"HideUI", (PyCFunction)Source_HideUI, METH_NOARGS, "replaceme"},
    {"GetXferFileName", (PyCFunction)Source_GetXferFileName, METH_NOARGS, "replaceme"},
    {"XferAudioByFile", (PyCFunction)Source_XferAudioByFile, METH_NOARGS, "replaceme"},
    {"destroy", (PyCFunction)Source_destroy, METH_NOARGS, "replaceme"},
    {NULL, NULL, 0, NULL}
};

static void
kill_Source(SourceObject* Source, boolean bHaveInterp)
{
	//	kill_Source is used to close down the source object. It is
	//	used in the destructor or by the system when the program
	//	is doing a forced exit.
	int  twRC = TWRC_FAILURE;
	TW_PENDINGXFERS twPendingXFers;
	int i;
	int pyErr = 0;

#if TRACE
printf("kill Source, thread %d\n", GetCurrentThreadId());
#endif 

	if (Source->pSM) { // In case done in wrong order

		for (i=0; i< MAX_SD_OBJECTS; i++) {
			if (AllSDObjects[i] == Source) {
				AllSDObjects[i] = NULL;
				break;
			}
		}

        // TODO: Only Call this if at state 7/6

		// State 7/6->5
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_PENDINGXFERS, MSG_RESET,
			(TW_MEMREF)&twPendingXFers, sizeof(twPendingXFers), &pyErr, bHaveInterp);
		
        // TODO: Only Call this if at state 5

		//	State 5->4
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			&Source->appID, DG_CONTROL, DAT_USERINTERFACE, MSG_DISABLEDS,
			(TW_MEMREF)&Source->twUI, sizeof(Source->twUI), &pyErr, bHaveInterp);

		//	State 4->3
		twRC = CallEntryPoint(Source->pSM->lpDSM_Entry, &Source->pSM->appID,
			NULL, DG_CONTROL, DAT_IDENTITY, MSG_CLOSEDS,
			(TW_MEMREF)&Source->appID, sizeof(Source->appID), &pyErr, bHaveInterp);

		Py_DECREF(Source->pSM);
		Source->pSM = NULL;
	}
#if TRACE
printf("kill Source returning\n");
#endif 

}

static void
dealloc_Source(SourceObject* Source)
{
#if TRACE
printf("dealloc Source, thread %d\n", GetCurrentThreadId());
#endif 
	kill_Source(Source, TRUE);

	PyObject_Del(Source);
}


static PyObject *
Source_getattr(SourceObject *self, char *name)
{
	return Py_FindMethod(Source_methods, (PyObject *)self, name);
}


static PyTypeObject SourceType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "Source",
    sizeof(SourceObject),
    0,
    (destructor)dealloc_Source, /*tp_dealloc*/
    0,          /*tp_print*/
    (getattrfunc)Source_getattr,          /*tp_getattr*/
    0,          /*tp_setattr*/
    0,          /*tp_compare*/
    0,          /*tp_repr*/
    0,          /*tp_as_number*/
    0,          /*tp_as_sequence*/
    0,          /*tp_as_mapping*/
    0,          /*tp_hash */
};
//---------------------------------------------------------------------------
/*
 * GlobalHeap Functions
 *
 * The twain interface uses the global heap for passing data
 * between the twain source and the application. The global heap
 * mechanism uses handles for accessing the data. This module
 * is intended for use by Python applications, which for some
 * reason, (i.e. to process a file which is in a strange format),
 * to access the heap, and manipulate the data on the heap.
 */

static char *pGlobalHandleGetBytes_doc = 
"Read a specified number of bytes from a global handle."
"The following parameters are required\n"
" Handle - a global handle\n"
" Offset - an index into the handle data\n"
" Count - The number of bytes to be returned\n";

static PyObject *
GlobalHandleGetBytes(PyObject *self, PyObject *args)
{
	HANDLE handle;
	long lOffset, lCount;
	void *pVoid;
	PyObject *rv;
	char szMessage[100];

	if (!PyArg_ParseTuple(args,"lll:GlobalHandleGetBytes", &handle, 
		&lOffset, &lCount))
		return NULL;

	if ((pVoid = GlobalLock(handle)) == NULL)
	{
		sprintf(szMessage, "Could Not Lock Bitmap Memory [0x%lx]", handle);
		PyErr_SetString(excGlobalHeap, szMessage); 
		return(NULL);
	}

	rv = Py_BuildValue("z#", (char *)pVoid + lOffset, lCount);
	GlobalUnlock(handle);
	return rv;
}

static char *pGlobalHandlePutBytes_doc = 
"Write a specified number of bytes to a global handle."
"The following parameters are required\n"
" Handle - a global handle\n"
" Offset - an index into the handle data\n"
" Count - The number of bytes to be returned\n"
" Data - String of data to be written\n";

static PyObject *
GlobalHandlePutBytes(PyObject *self, PyObject *args)
{
	HANDLE handle;
	long lOffset, lCount;
	void *pVoid, *pData;
	char szMessage[100];
	
	if (!PyArg_ParseTuple(args,"llls:GlobalHandlePutBytes", &handle, 
		&lOffset, &lCount, &pData))
		return NULL;

	if ((pVoid = GlobalLock(handle)) == NULL)
	{
		sprintf(szMessage, "Could Not Lock Bitmap Memory [0x%lx]", handle);
		PyErr_SetString(excGlobalHeap, szMessage); 
		return(NULL);
	}

	memcpy((char *)pVoid + lOffset, pData, lCount); 
	GlobalUnlock(handle);

	Py_INCREF(Py_None);
	return Py_None;
}


static char *pGlobalHandleAllocate_doc = 
"Allocate a specified number of bytes via a global handle."
"The following parameters are required\n"
" Size - The number of bytes to be allocated\n";

static PyObject *
GlobalHandleAllocate(PyObject *self, PyObject *args)
{
	HANDLE handle;
	long lSize;
	PyObject *rv;

	if (!PyArg_ParseTuple(args,"l:GlobalHandleAllocate", &lSize))
		return NULL;

	handle = GlobalAlloc(GHND, lSize);
	rv = Py_BuildValue("l", handle);
	return rv;
}

static char *pGlobalHandleFree_doc = 
"Free an allocated heap section via the global handle."
"The following parameters are required\n"
" handle - The number of bytes to be allocated\n";

static PyObject *
GlobalHandleFree(PyObject *self, PyObject *args)
{
	HANDLE handle;

	if (!PyArg_ParseTuple(args,"l:GlobalHandleFree", &handle))
		return NULL;

	handle = GlobalFree(handle);
	Py_INCREF(Py_None);
	return Py_None;
}

//---------------------------------------------------------------------------

static PyMethodDef methods[] = {
    {"SourceManager", (PyCFunction)new_SourceManager, METH_VARARGS|METH_KEYWORDS, "replaceme."},
    {"DIBToBMFile", (PyCFunction)DIBToBMFile, METH_VARARGS, "replaceme"},
    {"GlobalHandleGetBytes", (PyCFunction)GlobalHandleGetBytes, METH_VARARGS, "replaceme"},
    {"GlobalHandlePutBytes", (PyCFunction)GlobalHandlePutBytes, METH_VARARGS, "replaceme"},
    {"GlobalHandleAllocate", (PyCFunction)GlobalHandleAllocate, METH_VARARGS, "replaceme"},
    {"GlobalHandleFree", (PyCFunction)GlobalHandleFree, METH_VARARGS, "replaceme"},
    {"DIBToXBMFile", (PyCFunction)DIBToXBMFile, METH_VARARGS, "replaceme"},
    {"Version", (PyCFunction)Version, METH_VARARGS, "replaceme"},
    {NULL, NULL, 0, NULL}
};


#define DECLARE_CONST(id) PyDict_SetItemString(d, #id, Py_BuildValue("l", id))

DL_EXPORT(void)
inittwain(void) 
{
	PyObject *m, *d;

    SourceManagerType.ob_type = &PyType_Type;

	SourceManager_methods[0].ml_doc = pSourceManager_DSM_Entry_doc;
	SourceManager_methods[1].ml_doc = pSourceManager_ProcessEvent_doc;
	SourceManager_methods[2].ml_doc = pSourceManager_OpenSource_doc;
	SourceManager_methods[3].ml_doc = pSourceManager_GetSourceList_doc;
	SourceManager_methods[4].ml_doc = pSourceManager_SetCallback_doc;
	SourceManager_methods[5].ml_doc = pSourceManager_GetIdentity_doc;
	SourceManager_methods[6].ml_doc = pSourceManager_destroy_doc;

	Source_methods[0].ml_doc = pSource_DSM_Entry_doc;
	Source_methods[1].ml_doc = pSource_RequestAcquire_doc;
	Source_methods[2].ml_doc = pSource_GetCapability_doc;
	Source_methods[3].ml_doc = pSource_SetCapability_doc;
	Source_methods[4].ml_doc = pSource_GetImageInfo_doc;
	Source_methods[5].ml_doc = pSource_XferImageNatively_doc;
	Source_methods[6].ml_doc = pSource_GetCapabilityCurrent_doc;
	Source_methods[7].ml_doc = pSource_GetCapabilityDefault_doc;
	Source_methods[8].ml_doc = pSource_ResetCapability_doc;
	Source_methods[9].ml_doc = pSource_GetImageLayout_doc;
	Source_methods[10].ml_doc = pSource_SetImageLayout_doc;
	Source_methods[11].ml_doc = pSource_GetSourceName_doc;
	Source_methods[12].ml_doc = pSource_XferImageByFile_doc;
	Source_methods[13].ml_doc = pSource_SetXferFileName_doc;
	Source_methods[14].ml_doc = pSource_GetIdentity_doc;
	Source_methods[15].ml_doc = pSource_CancelOnePendingXfer_doc;
	Source_methods[16].ml_doc = pSource_CancelAllPendingXfers_doc;
	Source_methods[17].ml_doc = pSource_HideUI_doc;
	Source_methods[18].ml_doc = pSource_GetXferFileName_doc;
	Source_methods[19].ml_doc = pSource_XferAudioByFile_doc;
	Source_methods[20].ml_doc = pSource_destroy_doc;

	methods[0].ml_doc = pnew_SourceManager_doc;
	methods[1].ml_doc = pDIBToBMFile_doc;
	methods[2].ml_doc = pGlobalHandleGetBytes_doc;
	methods[3].ml_doc = pGlobalHandlePutBytes_doc;
	methods[4].ml_doc = pGlobalHandleAllocate_doc;
	methods[5].ml_doc = pGlobalHandleFree_doc;
	methods[6].ml_doc = pDIBToXBMFile_doc;
	methods[7].ml_doc = pVersion_doc;

	m = Py_InitModule("twain", methods);
	d = PyModule_GetDict(m);

    excSMLoadFileFailed = PyErr_NewException("twain.SMLoadFileFailed", NULL, NULL);
    PyDict_SetItemString(d, "excSMLoadFileFailed", excSMLoadFileFailed);
    excSMGetProcAddressFailed = PyErr_NewException("twain.SMGetProcAddressFailed", NULL, NULL);
    PyDict_SetItemString(d, "excSMGetProcAddressFailed", excSMGetProcAddressFailed);
    excSMOpenFailed = PyErr_NewException("twain.excSMOpenFailed", NULL, NULL);
    PyDict_SetItemString (d, "excSMOpenFailed", excSMOpenFailed);
    excDSOpenFailed = PyErr_NewException("twain.excDSOpenFailed", NULL, NULL);
    PyDict_SetItemString (d, "excDSOpenFailed", excDSOpenFailed);
    excDSNoImageAvailable = PyErr_NewException("twain.excDSNoImageAvailable", NULL, NULL);
    PyDict_SetItemString (d, "excDSNoImageAvailable", excDSNoImageAvailable);
    excDSTransferCancelled = PyErr_NewException("twain.excDSTransferCancelled", NULL, NULL);
    PyDict_SetItemString (d, "excDSTransferCancelled", excDSTransferCancelled);
    excCapabilityFormatNotSupported = PyErr_NewException("twain.excCapabilityFormatNotSupported", NULL, NULL);
    PyDict_SetItemString (d, "excCapabilityFormatNotSupported", excCapabilityFormatNotSupported);
    excBufferOverrun = PyErr_NewException("twain.excBufferOverrun", NULL, NULL);
    PyDict_SetItemString (d, "excBufferOverrun", excBufferOverrun);
    excGlobalHeap = PyErr_NewException("twain.excGlobalHeap", NULL, NULL);
    PyDict_SetItemString (d, "excGlobalHeap", excGlobalHeap);
    excImageFormat = PyErr_NewException("twain.excImageFormat", NULL, NULL);
    PyDict_SetItemString (d, "excImageFormat", excImageFormat);
    excFileError = PyErr_NewException("twain.excFileError", NULL, NULL);
    PyDict_SetItemString (d, "excFileError", excFileError);
    excMemoryError = PyErr_NewException("twain.excMemoryError", NULL, NULL);
    PyDict_SetItemString (d, "excMemoryError", excMemoryError);
    excParamError = PyErr_NewException("twain.excParamError", NULL, NULL);
    PyDict_SetItemString (d, "excParamError", excParamError);
    excInternalError = PyErr_NewException("twain.excInternalError", NULL, NULL);
    PyDict_SetItemString (d, "excInternalError", excInternalError);


    excTWCC_SUCCESS = PyErr_NewException("twain.excTWCC_SUCCESS", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_SUCCESS", excTWCC_SUCCESS);
    excTWCC_BUMMER = PyErr_NewException("twain.excTWCC_BUMMER", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_BUMMER", excTWCC_BUMMER);
    excTWCC_LOWMEMORY = PyErr_NewException("twain.excTWCC_LOWMEMORY", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_LOWMEMORY", excTWCC_LOWMEMORY);
    excTWCC_NODS = PyErr_NewException("twain.excTWCC_NODS", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_NODS", excTWCC_NODS);
    excTWCC_MAXCONNECTIONS = PyErr_NewException("twain.excTWCC_MAXCONNECTIONS", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_MAXCONNECTIONS", excTWCC_MAXCONNECTIONS);
    excTWCC_BADCAP = PyErr_NewException("twain.excTWCC_BADCAP", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_BADCAP", excTWCC_BADCAP);
    excTWCC_BADPROTOCOL = PyErr_NewException("twain.excTWCC_BADPROTOCOL", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_BADPROTOCOL", excTWCC_BADPROTOCOL);
    excTWCC_BADVALUE = PyErr_NewException("twain.excTWCC_BADVALUE", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_BADVALUE", excTWCC_BADVALUE);
    excTWCC_SEQERROR = PyErr_NewException("twain.excTWCC_SEQERROR", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_SEQERROR", excTWCC_SEQERROR);
    excTWCC_BADDEST = PyErr_NewException("twain.excTWCC_BADDEST", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_BADDEST", excTWCC_BADDEST);
    excTWCC_CAPUNSUPPORTED = PyErr_NewException("twain.excTWCC_CAPUNSUPPORTED", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_CAPUNSUPPORTED", excTWCC_CAPUNSUPPORTED);
    excTWCC_CAPBADOPERATION = PyErr_NewException("twain.excTWCC_CAPBADOPERATION", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_CAPBADOPERATION", excTWCC_CAPBADOPERATION);
    excTWCC_CAPSEQERROR = PyErr_NewException("twain.excTWCC_CAPSEQERROR", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_CAPSEQERROR", excTWCC_CAPSEQERROR);
    excTWCC_DENIED = PyErr_NewException("twain.excTWCC_DENIED", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_DENIED", excTWCC_DENIED);
    excTWCC_FILEEXISTS = PyErr_NewException("twain.excTWCC_FILEEXISTS", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_FILEEXISTS", excTWCC_FILEEXISTS);
    excTWCC_FILENOTFOUND = PyErr_NewException("twain.excTWCC_FILENOTFOUND", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_FILENOTFOUND", excTWCC_FILENOTFOUND);
    excTWCC_NOTEMPTY = PyErr_NewException("twain.excTWCC_NOTEMPTY", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_NOTEMPTY", excTWCC_NOTEMPTY);
    excTWCC_PAPERJAM = PyErr_NewException("twain.excTWCC_PAPERJAM", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_PAPERJAM", excTWCC_PAPERJAM);
    excTWCC_PAPERDOUBLEFEED = PyErr_NewException("twain.excTWCC_PAPERDOUBLEFEED", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_PAPERDOUBLEFEED", excTWCC_PAPERDOUBLEFEED);
    excTWCC_FILEWRITEERROR = PyErr_NewException("twain.excTWCC_FILEWRITEERROR", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_FILEWRITEERROR", excTWCC_FILEWRITEERROR);
    excTWCC_CHECKDEVICEONLINE = PyErr_NewException("twain.excTWCC_CHECKDEVICEONLINE", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_CHECKDEVICEONLINE", excTWCC_CHECKDEVICEONLINE);
    excTWCC_UNKNOWN = PyErr_NewException("twain.excTWCC_UNKNOWN", NULL, NULL);
    PyDict_SetItemString (d, "excTWCC_UNKNOWN", excTWCC_UNKNOWN);

	DECLARE_CONST(TWON_ARRAY);
	DECLARE_CONST(TWON_ENUMERATION);
    
	DECLARE_CONST(TWON_ONEVALUE);
	DECLARE_CONST(TWON_RANGE);

	DECLARE_CONST(TWON_ICONID);
	DECLARE_CONST(TWON_DSMID);
	DECLARE_CONST(TWON_DSMCODEID);

	DECLARE_CONST(TWON_DONTCARE8);
	DECLARE_CONST(TWON_DONTCARE16);
	DECLARE_CONST(TWON_DONTCARE32);

	DECLARE_CONST(TWMF_APPOWNS);
	DECLARE_CONST(TWMF_DSMOWNS);
	DECLARE_CONST(TWMF_DSOWNS);
	DECLARE_CONST(TWMF_POINTER);
	DECLARE_CONST(TWMF_HANDLE);

	DECLARE_CONST(TWPA_RGB);
	DECLARE_CONST(TWPA_GRAY);
	DECLARE_CONST(TWPA_CMY);

	DECLARE_CONST(TWTY_INT8);
	DECLARE_CONST(TWTY_INT16);
	DECLARE_CONST(TWTY_INT32);
	DECLARE_CONST(TWTY_UINT8);
	DECLARE_CONST(TWTY_UINT16);
	DECLARE_CONST(TWTY_UINT32);
	DECLARE_CONST(TWTY_BOOL);
	DECLARE_CONST(TWTY_FIX32);
	DECLARE_CONST(TWTY_FRAME);
	DECLARE_CONST(TWTY_STR32);
	DECLARE_CONST(TWTY_STR64);
	DECLARE_CONST(TWTY_STR128);
	DECLARE_CONST(TWTY_STR255);

#if defined(TWTY_STR1024)
    DECLARE_CONST(TWTY_STR1024);
#endif
#if defined(TWTY_UNI512)
    DECLARE_CONST(TWTY_UNI512);
#endif

	DECLARE_CONST(TWBO_LSBFIRST);
	DECLARE_CONST(TWBO_MSBFIRST);

#if defined(TWBP_DISABLE)
    DECLARE_CONST(TWBP_DISABLE);
#endif
#if defined(TWBP_AUTO)
    DECLARE_CONST(TWBP_AUTO);
#endif

	DECLARE_CONST(TWCP_NONE);
	DECLARE_CONST(TWCP_PACKBITS);
	DECLARE_CONST(TWCP_GROUP31D);
	DECLARE_CONST(TWCP_GROUP31DEOL);
	DECLARE_CONST(TWCP_GROUP32D);
	DECLARE_CONST(TWCP_GROUP4);
	DECLARE_CONST(TWCP_JPEG);
	DECLARE_CONST(TWCP_LZW);
	DECLARE_CONST(TWCP_JBIG);
	DECLARE_CONST(TWCP_PNG);
	DECLARE_CONST(TWCP_RLE4);
	DECLARE_CONST(TWCP_RLE8);
	DECLARE_CONST(TWCP_BITFIELDS);

#if defined(TWCS_BOTH)
    DECLARE_CONST(TWCS_BOTH);
#endif
#if defined(TWCS_TOP)
    DECLARE_CONST(TWCS_TOP);
#endif
#if defined(TWCS_BOTTOM)
    DECLARE_CONST(TWCS_BOTTOM);
#endif

	DECLARE_CONST(TWFF_TIFF);
	DECLARE_CONST(TWFF_PICT);
	DECLARE_CONST(TWFF_BMP);
	DECLARE_CONST(TWFF_XBM);
	DECLARE_CONST(TWFF_JFIF);
	DECLARE_CONST(TWFF_FPX);
	DECLARE_CONST(TWFF_TIFFMULTI);
	DECLARE_CONST(TWFF_PNG);
	DECLARE_CONST(TWFF_SPIFF);
	DECLARE_CONST(TWFF_EXIF);
#if defined(TWFF_PDF)
    DECLARE_CONST(TWFF_PDF);
#endif
#if defined(TWFF_JP2)
    DECLARE_CONST(TWFF_JP2);
#endif
#if defined(TWFF_JPX)
    DECLARE_CONST(TWFF_JPX);
#endif
#if defined(TWFF_DEJAVU)
    DECLARE_CONST(TWFF_DEJAVU);
#endif
#if defined(TWFF_PDFA)
    DECLARE_CONST(TWFF_PDFA);
#endif
#if defined(TWFF_PDFA2)
    DECLARE_CONST(TWFF_PDFA2);
#endif

	DECLARE_CONST(TWFT_RED);
	DECLARE_CONST(TWFT_GREEN);
	DECLARE_CONST(TWFT_BLUE);
	DECLARE_CONST(TWFT_NONE);
	DECLARE_CONST(TWFT_WHITE);
	DECLARE_CONST(TWFT_CYAN);
	DECLARE_CONST(TWFT_MAGENTA);
	DECLARE_CONST(TWFT_YELLOW);
	DECLARE_CONST(TWFT_BLACK);

	DECLARE_CONST(TWLP_REFLECTIVE);
	DECLARE_CONST(TWLP_TRANSMISSIVE);

	DECLARE_CONST(TWLS_RED);
	DECLARE_CONST(TWLS_GREEN);
	DECLARE_CONST(TWLS_BLUE);
	DECLARE_CONST(TWLS_NONE);
	DECLARE_CONST(TWLS_WHITE);
	DECLARE_CONST(TWLS_UV);
	DECLARE_CONST(TWLS_IR);

	DECLARE_CONST(TWOR_ROT0);
	DECLARE_CONST(TWOR_ROT90);
	DECLARE_CONST(TWOR_ROT180);
	DECLARE_CONST(TWOR_ROT270);
	DECLARE_CONST(TWOR_PORTRAIT);
	DECLARE_CONST(TWOR_LANDSCAPE);

	DECLARE_CONST(TWPC_CHUNKY);
	DECLARE_CONST(TWPC_PLANAR);

	DECLARE_CONST(TWPF_CHOCOLATE);
	DECLARE_CONST(TWPF_VANILLA);

	DECLARE_CONST(TWPT_BW);
	DECLARE_CONST(TWPT_GRAY);
	DECLARE_CONST(TWPT_RGB);
	DECLARE_CONST(TWPT_PALETTE);
	DECLARE_CONST(TWPT_CMY);
	DECLARE_CONST(TWPT_CMYK);
	DECLARE_CONST(TWPT_YUV);
	DECLARE_CONST(TWPT_YUVK);
	DECLARE_CONST(TWPT_CIEXYZ);

	DECLARE_CONST(TWSS_NONE);
	DECLARE_CONST(TWSS_A4LETTER);
	DECLARE_CONST(TWSS_B5LETTER);
	DECLARE_CONST(TWSS_USLETTER);
	DECLARE_CONST(TWSS_USLEGAL);
	DECLARE_CONST(TWSS_A5);
	DECLARE_CONST(TWSS_B4);
	DECLARE_CONST(TWSS_B6);
	DECLARE_CONST(TWSS_USLEDGER);
	DECLARE_CONST(TWSS_USEXECUTIVE);
	DECLARE_CONST(TWSS_A3);
	DECLARE_CONST(TWSS_B3);
	DECLARE_CONST(TWSS_A6);
	DECLARE_CONST(TWSS_C4);
	DECLARE_CONST(TWSS_C5);
	DECLARE_CONST(TWSS_C6);
	DECLARE_CONST(TWSS_4A0);
	DECLARE_CONST(TWSS_2A0);
	DECLARE_CONST(TWSS_A0);
	DECLARE_CONST(TWSS_A1);
	DECLARE_CONST(TWSS_A2);
	DECLARE_CONST(TWSS_A4);
	DECLARE_CONST(TWSS_A7);
	DECLARE_CONST(TWSS_A8);
	DECLARE_CONST(TWSS_A9);
	DECLARE_CONST(TWSS_A10);
	DECLARE_CONST(TWSS_ISOB0);
	DECLARE_CONST(TWSS_ISOB1);
	DECLARE_CONST(TWSS_ISOB2);
	DECLARE_CONST(TWSS_ISOB3);
	DECLARE_CONST(TWSS_ISOB4);
	DECLARE_CONST(TWSS_ISOB5);
	DECLARE_CONST(TWSS_ISOB6);
	DECLARE_CONST(TWSS_ISOB7);
	DECLARE_CONST(TWSS_ISOB8);
	DECLARE_CONST(TWSS_ISOB9);
	DECLARE_CONST(TWSS_ISOB10);
	DECLARE_CONST(TWSS_JISB0);
	DECLARE_CONST(TWSS_JISB1);
	DECLARE_CONST(TWSS_JISB2);
	DECLARE_CONST(TWSS_JISB3);
	DECLARE_CONST(TWSS_JISB4);
	DECLARE_CONST(TWSS_JISB5);
	DECLARE_CONST(TWSS_JISB6);
	DECLARE_CONST(TWSS_JISB7);
	DECLARE_CONST(TWSS_JISB8);
	DECLARE_CONST(TWSS_JISB9);
	DECLARE_CONST(TWSS_JISB10);
	DECLARE_CONST(TWSS_C0);
	DECLARE_CONST(TWSS_C1);
	DECLARE_CONST(TWSS_C2);
	DECLARE_CONST(TWSS_C3);
	DECLARE_CONST(TWSS_C7);
	DECLARE_CONST(TWSS_C8);
	DECLARE_CONST(TWSS_C9);
	DECLARE_CONST(TWSS_C10);
	DECLARE_CONST(TWSS_USSTATEMENT);
	DECLARE_CONST(TWSS_BUSINESSCARD);

	DECLARE_CONST(TWSX_NATIVE);
	DECLARE_CONST(TWSX_FILE);
	DECLARE_CONST(TWSX_MEMORY);

	DECLARE_CONST(TWUN_INCHES);
	DECLARE_CONST(TWUN_CENTIMETERS);
	DECLARE_CONST(TWUN_PICAS);
	DECLARE_CONST(TWUN_POINTS);
	DECLARE_CONST(TWUN_TWIPS);
	DECLARE_CONST(TWUN_PIXELS);

	DECLARE_CONST(TWBR_THRESHOLD);
	DECLARE_CONST(TWBR_HALFTONE);
	DECLARE_CONST(TWBR_CUSTHALFTONE);
	DECLARE_CONST(TWBR_DIFFUSION);

	DECLARE_CONST(TWDX_NONE);
	DECLARE_CONST(TWDX_1PASSDUPLEX);
	DECLARE_CONST(TWDX_2PASSDUPLEX);

	DECLARE_CONST(TWBT_3OF9);
	DECLARE_CONST(TWBT_2OF5INTERLEAVED);
	DECLARE_CONST(TWBT_2OF5NONINTERLEAVED);
	DECLARE_CONST(TWBT_CODE93);
	DECLARE_CONST(TWBT_CODE128);
	DECLARE_CONST(TWBT_UCC128);
	DECLARE_CONST(TWBT_CODABAR);
	DECLARE_CONST(TWBT_UPCA);
	DECLARE_CONST(TWBT_UPCE);
	DECLARE_CONST(TWBT_EAN8);
	DECLARE_CONST(TWBT_EAN13);
	DECLARE_CONST(TWBT_POSTNET);
	DECLARE_CONST(TWBT_PDF417);
	DECLARE_CONST(TWBT_2OF5INDUSTRIAL);
	DECLARE_CONST(TWBT_2OF5MATRIX);
	DECLARE_CONST(TWBT_2OF5DATALOGIC);
	DECLARE_CONST(TWBT_2OF5IATA);
	DECLARE_CONST(TWBT_3OF9FULLASCII);
	DECLARE_CONST(TWBT_CODABARWITHSTARTSTOP);
	DECLARE_CONST(TWBT_MAXICODE);

	DECLARE_CONST(TWDSK_SUCCESS);
	DECLARE_CONST(TWDSK_REPORTONLY);
	DECLARE_CONST(TWDSK_FAIL);
	DECLARE_CONST(TWDSK_DISABLED);

	DECLARE_CONST(TWPCH_PATCH1);
	DECLARE_CONST(TWPCH_PATCH2);
	DECLARE_CONST(TWPCH_PATCH3);
	DECLARE_CONST(TWPCH_PATCH4);
	DECLARE_CONST(TWPCH_PATCH6);
	DECLARE_CONST(TWPCH_PATCHT);

	DECLARE_CONST(TWJC_NONE);
	DECLARE_CONST(TWJC_JSIC);
	DECLARE_CONST(TWJC_JSIS);
	DECLARE_CONST(TWJC_JSXC);
	DECLARE_CONST(TWJC_JSXS);

	DECLARE_CONST(TWBCOR_ROT0);
	DECLARE_CONST(TWBCOR_ROT90);
	DECLARE_CONST(TWBCOR_ROT180);
	DECLARE_CONST(TWBCOR_ROT270);
	DECLARE_CONST(TWBCOR_ROTX);

	DECLARE_CONST(TWAF_WAV);
	DECLARE_CONST(TWAF_AIFF);
	DECLARE_CONST(TWAF_AU);
	DECLARE_CONST(TWAF_SND);

	DECLARE_CONST(TWAL_ALARM);
	DECLARE_CONST(TWAL_FEEDERERROR);
	DECLARE_CONST(TWAL_FEEDERWARNING);
	DECLARE_CONST(TWAL_BARCODE);
	DECLARE_CONST(TWAL_DOUBLEFEED);
	DECLARE_CONST(TWAL_JAM);
	DECLARE_CONST(TWAL_PATCHCODE);
	DECLARE_CONST(TWAL_POWER);
	DECLARE_CONST(TWAL_SKEW);

#if defined(TWAS_NONE)
    DECLARE_CONST(TWAS_NONE);
#endif
#if defined(TWAS_AUTO)
    DECLARE_CONST(TWAS_AUTO);
#endif
#if defined(TWAS_CURRENT)
    DECLARE_CONST(TWAS_CURRENT);
#endif

	DECLARE_CONST(TWCB_AUTO);
	DECLARE_CONST(TWCB_CLEAR);
	DECLARE_CONST(TWCB_NOCLEAR);

	DECLARE_CONST(TWDE_CUSTOMEVENTS);
	DECLARE_CONST(TWDE_CHECKAUTOMATICCAPTURE);
	DECLARE_CONST(TWDE_CHECKBATTERY);
	DECLARE_CONST(TWDE_CHECKDEVICEONLINE);
	DECLARE_CONST(TWDE_CHECKFLASH);
	DECLARE_CONST(TWDE_CHECKPOWERSUPPLY);
	DECLARE_CONST(TWDE_CHECKRESOLUTION);
	DECLARE_CONST(TWDE_DEVICEADDED);
	DECLARE_CONST(TWDE_DEVICEOFFLINE);
	DECLARE_CONST(TWDE_DEVICEREADY);
	DECLARE_CONST(TWDE_DEVICEREMOVED);
	DECLARE_CONST(TWDE_IMAGECAPTURED);
	DECLARE_CONST(TWDE_IMAGEDELETED);
	DECLARE_CONST(TWDE_PAPERDOUBLEFEED);
	DECLARE_CONST(TWDE_PAPERJAM);
	DECLARE_CONST(TWDE_LAMPFAILURE);
	DECLARE_CONST(TWDE_POWERSAVE);
	DECLARE_CONST(TWDE_POWERSAVENOTIFY);

#if defined(TWDR_GET)
    DECLARE_CONST(TWDR_GET);
#endif
#if defined(TWDR_SET)
    DECLARE_CONST(TWDR_SET);
#endif

	DECLARE_CONST(TWFA_NONE);
	DECLARE_CONST(TWFA_LEFT);
	DECLARE_CONST(TWFA_CENTER);
	DECLARE_CONST(TWFA_RIGHT);

#if defined(TWFE_GENERAL)
    DECLARE_CONST(TWFE_GENERAL);
#endif
#if defined(TWFE_PHOTO)
    DECLARE_CONST(TWFE_PHOTO);
#endif

	DECLARE_CONST(TWFO_FIRSTPAGEFIRST);
	DECLARE_CONST(TWFO_LASTPAGEFIRST);

	DECLARE_CONST(TWFS_FILESYSTEM);
	DECLARE_CONST(TWFS_RECURSIVEDELETE);
	DECLARE_CONST(TWPS_EXTERNAL);
	DECLARE_CONST(TWPS_BATTERY);

	DECLARE_CONST(TWPR_IMPRINTERTOPBEFORE);
	DECLARE_CONST(TWPR_IMPRINTERTOPAFTER);
	DECLARE_CONST(TWPR_IMPRINTERBOTTOMBEFORE);
	DECLARE_CONST(TWPR_IMPRINTERBOTTOMAFTER);
	DECLARE_CONST(TWPR_ENDORSERTOPBEFORE);
	DECLARE_CONST(TWPR_ENDORSERTOPAFTER);
	DECLARE_CONST(TWPR_ENDORSERBOTTOMBEFORE);
	DECLARE_CONST(TWPR_ENDORSERBOTTOMAFTER);

	DECLARE_CONST(TWPM_SINGLESTRING);
	DECLARE_CONST(TWPM_MULTISTRING);
	DECLARE_CONST(TWPM_COMPOUNDSTRING);

	DECLARE_CONST(TWBD_HORZ);
	DECLARE_CONST(TWBD_VERT);
	DECLARE_CONST(TWBD_HORZVERT);
	DECLARE_CONST(TWBD_VERTHORZ);

	DECLARE_CONST(TWFL_NONE);
	DECLARE_CONST(TWFL_OFF);
	DECLARE_CONST(TWFL_ON);
	DECLARE_CONST(TWFL_AUTO);
	DECLARE_CONST(TWFL_REDEYE);

	DECLARE_CONST(TWFR_BOOK);
	DECLARE_CONST(TWFR_FANFOLD);

	DECLARE_CONST(TWIF_NONE);
	DECLARE_CONST(TWIF_AUTO);
	DECLARE_CONST(TWIF_LOWPASS);
	DECLARE_CONST(TWIF_BANDPASS);
	DECLARE_CONST(TWIF_HIGHPASS);
	DECLARE_CONST(TWIF_TEXT);
	DECLARE_CONST(TWIF_FINELINE);

	DECLARE_CONST(TWNF_NONE);
	DECLARE_CONST(TWNF_AUTO);
	DECLARE_CONST(TWNF_LONEPIXEL);
	DECLARE_CONST(TWNF_MAJORITYRULE);

	DECLARE_CONST(TWOV_NONE);
	DECLARE_CONST(TWOV_AUTO);
	DECLARE_CONST(TWOV_TOPBOTTOM);
	DECLARE_CONST(TWOV_LEFTRIGHT);
	DECLARE_CONST(TWOV_ALL);

	DECLARE_CONST(TWFY_CAMERA);
	DECLARE_CONST(TWFY_CAMERATOP);
	DECLARE_CONST(TWFY_CAMERABOTTOM);
	DECLARE_CONST(TWFY_CAMERAPREVIEW);
	DECLARE_CONST(TWFY_DOMAIN);
	DECLARE_CONST(TWFY_HOST);
	DECLARE_CONST(TWFY_DIRECTORY);
	DECLARE_CONST(TWFY_IMAGE);
	DECLARE_CONST(TWFY_UNKNOWN);

	DECLARE_CONST(TWCY_AFGHANISTAN);
	DECLARE_CONST(TWCY_ALGERIA);
	DECLARE_CONST(TWCY_AMERICANSAMOA);
	DECLARE_CONST(TWCY_ANDORRA);
	DECLARE_CONST(TWCY_ANGOLA);
	DECLARE_CONST(TWCY_ANGUILLA);
	DECLARE_CONST(TWCY_ANTIGUA);
	DECLARE_CONST(TWCY_ARGENTINA);
	DECLARE_CONST(TWCY_ARUBA);
	DECLARE_CONST(TWCY_ASCENSIONI);
	DECLARE_CONST(TWCY_AUSTRALIA);
	DECLARE_CONST(TWCY_AUSTRIA);
	DECLARE_CONST(TWCY_BAHAMAS);
	DECLARE_CONST(TWCY_BAHRAIN);
	DECLARE_CONST(TWCY_BANGLADESH);
	DECLARE_CONST(TWCY_BARBADOS);
	DECLARE_CONST(TWCY_BELGIUM);
	DECLARE_CONST(TWCY_BELIZE);
	DECLARE_CONST(TWCY_BENIN);
	DECLARE_CONST(TWCY_BERMUDA);
	DECLARE_CONST(TWCY_BHUTAN);
	DECLARE_CONST(TWCY_BOLIVIA);
	DECLARE_CONST(TWCY_BOTSWANA);
	DECLARE_CONST(TWCY_BRITAIN);
	DECLARE_CONST(TWCY_BRITVIRGINIS);
	DECLARE_CONST(TWCY_BRAZIL);
	DECLARE_CONST(TWCY_BRUNEI);
	DECLARE_CONST(TWCY_BULGARIA);
	DECLARE_CONST(TWCY_BURKINAFASO);
	DECLARE_CONST(TWCY_BURMA);
	DECLARE_CONST(TWCY_BURUNDI);
	DECLARE_CONST(TWCY_CAMAROON);
	DECLARE_CONST(TWCY_CANADA);
	DECLARE_CONST(TWCY_CAPEVERDEIS);
	DECLARE_CONST(TWCY_CAYMANIS);
	DECLARE_CONST(TWCY_CENTRALAFREP);
	DECLARE_CONST(TWCY_CHAD);
	DECLARE_CONST(TWCY_CHILE);
	DECLARE_CONST(TWCY_CHINA);
	DECLARE_CONST(TWCY_CHRISTMASIS);
	DECLARE_CONST(TWCY_COCOSIS);
	DECLARE_CONST(TWCY_COLOMBIA);
	DECLARE_CONST(TWCY_COMOROS);
	DECLARE_CONST(TWCY_CONGO);
	DECLARE_CONST(TWCY_COOKIS);
	DECLARE_CONST(TWCY_COSTARICA);
	DECLARE_CONST(TWCY_CUBA);
	DECLARE_CONST(TWCY_CYPRUS);
	DECLARE_CONST(TWCY_CZECHOSLOVAKIA);
	DECLARE_CONST(TWCY_DENMARK);
	DECLARE_CONST(TWCY_DJIBOUTI);
	DECLARE_CONST(TWCY_DOMINICA);
	DECLARE_CONST(TWCY_DOMINCANREP);
	DECLARE_CONST(TWCY_EASTERIS);
	DECLARE_CONST(TWCY_ECUADOR);
	DECLARE_CONST(TWCY_EGYPT);
	DECLARE_CONST(TWCY_ELSALVADOR);
	DECLARE_CONST(TWCY_EQGUINEA);
	DECLARE_CONST(TWCY_ETHIOPIA);
	DECLARE_CONST(TWCY_FALKLANDIS);
	DECLARE_CONST(TWCY_FAEROEIS);
	DECLARE_CONST(TWCY_FIJIISLANDS);
	DECLARE_CONST(TWCY_FINLAND);
	DECLARE_CONST(TWCY_FRANCE);
	DECLARE_CONST(TWCY_FRANTILLES);
	DECLARE_CONST(TWCY_FRGUIANA);
	DECLARE_CONST(TWCY_FRPOLYNEISA);
	DECLARE_CONST(TWCY_FUTANAIS);
	DECLARE_CONST(TWCY_GABON);
	DECLARE_CONST(TWCY_GAMBIA);
	DECLARE_CONST(TWCY_GERMANY);
	DECLARE_CONST(TWCY_GHANA);
	DECLARE_CONST(TWCY_GIBRALTER);
	DECLARE_CONST(TWCY_GREECE);
	DECLARE_CONST(TWCY_GREENLAND);
	DECLARE_CONST(TWCY_GRENADA);
	DECLARE_CONST(TWCY_GRENEDINES);
	DECLARE_CONST(TWCY_GUADELOUPE);
	DECLARE_CONST(TWCY_GUAM);
	DECLARE_CONST(TWCY_GUANTANAMOBAY);
	DECLARE_CONST(TWCY_GUATEMALA);
	DECLARE_CONST(TWCY_GUINEA);
	DECLARE_CONST(TWCY_GUINEABISSAU);
	DECLARE_CONST(TWCY_GUYANA);
	DECLARE_CONST(TWCY_HAITI);
	DECLARE_CONST(TWCY_HONDURAS);
	DECLARE_CONST(TWCY_HONGKONG);
	DECLARE_CONST(TWCY_HUNGARY);
	DECLARE_CONST(TWCY_ICELAND);
	DECLARE_CONST(TWCY_INDIA);
	DECLARE_CONST(TWCY_INDONESIA);
	DECLARE_CONST(TWCY_IRAN);
	DECLARE_CONST(TWCY_IRAQ);
	DECLARE_CONST(TWCY_IRELAND);
	DECLARE_CONST(TWCY_ISRAEL);
	DECLARE_CONST(TWCY_ITALY);
	DECLARE_CONST(TWCY_IVORYCOAST);
	DECLARE_CONST(TWCY_JAMAICA);
	DECLARE_CONST(TWCY_JAPAN);
	DECLARE_CONST(TWCY_JORDAN);
	DECLARE_CONST(TWCY_KENYA);
	DECLARE_CONST(TWCY_KIRIBATI);
	DECLARE_CONST(TWCY_KOREA);
	DECLARE_CONST(TWCY_KUWAIT);
	DECLARE_CONST(TWCY_LAOS);
	DECLARE_CONST(TWCY_LEBANON);
	DECLARE_CONST(TWCY_LIBERIA);
	DECLARE_CONST(TWCY_LIBYA);
	DECLARE_CONST(TWCY_LIECHTENSTEIN);
	DECLARE_CONST(TWCY_LUXENBOURG);
	DECLARE_CONST(TWCY_MACAO);
	DECLARE_CONST(TWCY_MADAGASCAR);
	DECLARE_CONST(TWCY_MALAWI);
	DECLARE_CONST(TWCY_MALAYSIA);
	DECLARE_CONST(TWCY_MALDIVES);
	DECLARE_CONST(TWCY_MALI);
	DECLARE_CONST(TWCY_MALTA);
	DECLARE_CONST(TWCY_MARSHALLIS);
	DECLARE_CONST(TWCY_MAURITANIA);
	DECLARE_CONST(TWCY_MAURITIUS);
	DECLARE_CONST(TWCY_MEXICO);
	DECLARE_CONST(TWCY_MICRONESIA);
	DECLARE_CONST(TWCY_MIQUELON);
	DECLARE_CONST(TWCY_MONACO);
	DECLARE_CONST(TWCY_MONGOLIA);
	DECLARE_CONST(TWCY_MONTSERRAT);
	DECLARE_CONST(TWCY_MOROCCO);
	DECLARE_CONST(TWCY_MOZAMBIQUE);
	DECLARE_CONST(TWCY_NAMIBIA);
	DECLARE_CONST(TWCY_NAURU);
	DECLARE_CONST(TWCY_NEPAL);
	DECLARE_CONST(TWCY_NETHERLANDS);
	DECLARE_CONST(TWCY_NETHANTILLES);
	DECLARE_CONST(TWCY_NEVIS);
	DECLARE_CONST(TWCY_NEWCALEDONIA);
	DECLARE_CONST(TWCY_NEWZEALAND);
	DECLARE_CONST(TWCY_NICARAGUA);
	DECLARE_CONST(TWCY_NIGER);
	DECLARE_CONST(TWCY_NIGERIA);
	DECLARE_CONST(TWCY_NIUE);
	DECLARE_CONST(TWCY_NORFOLKI);
	DECLARE_CONST(TWCY_NORWAY);
	DECLARE_CONST(TWCY_OMAN);
	DECLARE_CONST(TWCY_PAKISTAN);
	DECLARE_CONST(TWCY_PALAU);
	DECLARE_CONST(TWCY_PANAMA);
	DECLARE_CONST(TWCY_PARAGUAY);
	DECLARE_CONST(TWCY_PERU);
	DECLARE_CONST(TWCY_PHILLIPPINES);
	DECLARE_CONST(TWCY_PITCAIRNIS);
	DECLARE_CONST(TWCY_PNEWGUINEA);
	DECLARE_CONST(TWCY_POLAND);
	DECLARE_CONST(TWCY_PORTUGAL);
	DECLARE_CONST(TWCY_QATAR);
	DECLARE_CONST(TWCY_REUNIONI);
	DECLARE_CONST(TWCY_ROMANIA);
	DECLARE_CONST(TWCY_RWANDA);
	DECLARE_CONST(TWCY_SAIPAN);
	DECLARE_CONST(TWCY_SANMARINO);
	DECLARE_CONST(TWCY_SAOTOME);
	DECLARE_CONST(TWCY_SAUDIARABIA);
	DECLARE_CONST(TWCY_SENEGAL);
	DECLARE_CONST(TWCY_SEYCHELLESIS);
	DECLARE_CONST(TWCY_SIERRALEONE);
	DECLARE_CONST(TWCY_SINGAPORE);
	DECLARE_CONST(TWCY_SOLOMONIS);
	DECLARE_CONST(TWCY_SOMALI);
	DECLARE_CONST(TWCY_SOUTHAFRICA);
	DECLARE_CONST(TWCY_SPAIN);
	DECLARE_CONST(TWCY_SRILANKA);
	DECLARE_CONST(TWCY_STHELENA);
	DECLARE_CONST(TWCY_STKITTS);
	DECLARE_CONST(TWCY_STLUCIA);
	DECLARE_CONST(TWCY_STPIERRE);
	DECLARE_CONST(TWCY_STVINCENT);
	DECLARE_CONST(TWCY_SUDAN);
	DECLARE_CONST(TWCY_SURINAME);
	DECLARE_CONST(TWCY_SWAZILAND);
	DECLARE_CONST(TWCY_SWEDEN);
	DECLARE_CONST(TWCY_SWITZERLAND);
	DECLARE_CONST(TWCY_SYRIA);
	DECLARE_CONST(TWCY_TAIWAN);
	DECLARE_CONST(TWCY_TANZANIA);
	DECLARE_CONST(TWCY_THAILAND);
	DECLARE_CONST(TWCY_TOBAGO);
	DECLARE_CONST(TWCY_TOGO);
	DECLARE_CONST(TWCY_TONGAIS);
	DECLARE_CONST(TWCY_TRINIDAD);
	DECLARE_CONST(TWCY_TUNISIA);
	DECLARE_CONST(TWCY_TURKEY);
	DECLARE_CONST(TWCY_TURKSCAICOS);
	DECLARE_CONST(TWCY_TUVALU);
	DECLARE_CONST(TWCY_UGANDA);
	DECLARE_CONST(TWCY_USSR);
	DECLARE_CONST(TWCY_UAEMIRATES);
	DECLARE_CONST(TWCY_UNITEDKINGDOM);
	DECLARE_CONST(TWCY_USA);
	DECLARE_CONST(TWCY_URUGUAY);
	DECLARE_CONST(TWCY_VANUATU);
	DECLARE_CONST(TWCY_VATICANCITY);
	DECLARE_CONST(TWCY_VENEZUELA);
	DECLARE_CONST(TWCY_WAKE);
	DECLARE_CONST(TWCY_WALLISIS);
	DECLARE_CONST(TWCY_WESTERNSAHARA);
	DECLARE_CONST(TWCY_WESTERNSAMOA);
	DECLARE_CONST(TWCY_YEMEN);
	DECLARE_CONST(TWCY_YUGOSLAVIA);
	DECLARE_CONST(TWCY_ZAIRE);
	DECLARE_CONST(TWCY_ZAMBIA);
	DECLARE_CONST(TWCY_ZIMBABWE);
	DECLARE_CONST(TWCY_ALBANIA);
	DECLARE_CONST(TWCY_ARMENIA);
	DECLARE_CONST(TWCY_AZERBAIJAN);
	DECLARE_CONST(TWCY_BELARUS);
	DECLARE_CONST(TWCY_BOSNIAHERZGO);
	DECLARE_CONST(TWCY_CAMBODIA);
	DECLARE_CONST(TWCY_CROATIA);
	DECLARE_CONST(TWCY_CZECHREPUBLIC);
	DECLARE_CONST(TWCY_DIEGOGARCIA);
	DECLARE_CONST(TWCY_ERITREA);
	DECLARE_CONST(TWCY_ESTONIA);
	DECLARE_CONST(TWCY_GEORGIA);
	DECLARE_CONST(TWCY_LATVIA);
	DECLARE_CONST(TWCY_LESOTHO);
	DECLARE_CONST(TWCY_LITHUANIA);
	DECLARE_CONST(TWCY_MACEDONIA);
	DECLARE_CONST(TWCY_MAYOTTEIS);
	DECLARE_CONST(TWCY_MOLDOVA);
	DECLARE_CONST(TWCY_MYANMAR);
	DECLARE_CONST(TWCY_NORTHKOREA);
	DECLARE_CONST(TWCY_PUERTORICO);
	DECLARE_CONST(TWCY_RUSSIA);
	DECLARE_CONST(TWCY_SERBIA);
	DECLARE_CONST(TWCY_SLOVAKIA);
	DECLARE_CONST(TWCY_SLOVENIA);
	DECLARE_CONST(TWCY_SOUTHKOREA);
	DECLARE_CONST(TWCY_UKRAINE);
	DECLARE_CONST(TWCY_USVIRGINIS);
	DECLARE_CONST(TWCY_VIETNAM);

	DECLARE_CONST(TWLG_DAN);
	DECLARE_CONST(TWLG_DUT);
	DECLARE_CONST(TWLG_ENG);
	DECLARE_CONST(TWLG_FCF);
	DECLARE_CONST(TWLG_FIN);
	DECLARE_CONST(TWLG_FRN);
	DECLARE_CONST(TWLG_GER);
	DECLARE_CONST(TWLG_ICE);
	DECLARE_CONST(TWLG_ITN);
	DECLARE_CONST(TWLG_NOR);
	DECLARE_CONST(TWLG_POR);
	DECLARE_CONST(TWLG_SPA);
	DECLARE_CONST(TWLG_SWE);
	DECLARE_CONST(TWLG_USA);
	DECLARE_CONST(TWLG_USERLOCALE);
	DECLARE_CONST(TWLG_AFRIKAANS);
	DECLARE_CONST(TWLG_ALBANIA);
	DECLARE_CONST(TWLG_ARABIC);
	DECLARE_CONST(TWLG_ARABIC_ALGERIA);
	DECLARE_CONST(TWLG_ARABIC_BAHRAIN);
	DECLARE_CONST(TWLG_ARABIC_EGYPT);
	DECLARE_CONST(TWLG_ARABIC_IRAQ);
	DECLARE_CONST(TWLG_ARABIC_JORDAN);
	DECLARE_CONST(TWLG_ARABIC_KUWAIT);
	DECLARE_CONST(TWLG_ARABIC_LEBANON);
	DECLARE_CONST(TWLG_ARABIC_LIBYA);
	DECLARE_CONST(TWLG_ARABIC_MOROCCO);
	DECLARE_CONST(TWLG_ARABIC_OMAN);
	DECLARE_CONST(TWLG_ARABIC_QATAR);
	DECLARE_CONST(TWLG_ARABIC_SAUDIARABIA);
	DECLARE_CONST(TWLG_ARABIC_SYRIA);
	DECLARE_CONST(TWLG_ARABIC_TUNISIA);
	DECLARE_CONST(TWLG_ARABIC_UAE);
	DECLARE_CONST(TWLG_ARABIC_YEMEN);
	DECLARE_CONST(TWLG_BASQUE);
	DECLARE_CONST(TWLG_BYELORUSSIAN);
	DECLARE_CONST(TWLG_BULGARIAN);
	DECLARE_CONST(TWLG_CATALAN);
	DECLARE_CONST(TWLG_CHINESE);
	DECLARE_CONST(TWLG_CHINESE_HONGKONG);
	DECLARE_CONST(TWLG_CHINESE_PRC);
	DECLARE_CONST(TWLG_CHINESE_SINGAPORE);
	DECLARE_CONST(TWLG_CHINESE_SIMPLIFIED);
	DECLARE_CONST(TWLG_CHINESE_TAIWAN);
	DECLARE_CONST(TWLG_CHINESE_TRADITIONAL);
	DECLARE_CONST(TWLG_CROATIA);
	DECLARE_CONST(TWLG_CZECH);
	DECLARE_CONST(TWLG_DANISH);
	DECLARE_CONST(TWLG_DUTCH);
	DECLARE_CONST(TWLG_DUTCH_BELGIAN);
	DECLARE_CONST(TWLG_ENGLISH);
	DECLARE_CONST(TWLG_ENGLISH_AUSTRALIAN);
	DECLARE_CONST(TWLG_ENGLISH_CANADIAN);
	DECLARE_CONST(TWLG_ENGLISH_IRELAND);
	DECLARE_CONST(TWLG_ENGLISH_NEWZEALAND);
	DECLARE_CONST(TWLG_ENGLISH_SOUTHAFRICA);
	DECLARE_CONST(TWLG_ENGLISH_UK);
	DECLARE_CONST(TWLG_ENGLISH_USA);
	DECLARE_CONST(TWLG_ESTONIAN);
	DECLARE_CONST(TWLG_FAEROESE);
	DECLARE_CONST(TWLG_FARSI);
	DECLARE_CONST(TWLG_FINNISH);
	DECLARE_CONST(TWLG_FRENCH);
	DECLARE_CONST(TWLG_FRENCH_BELGIAN);
	DECLARE_CONST(TWLG_FRENCH_CANADIAN);
	DECLARE_CONST(TWLG_FRENCH_LUXEMBOURG);
	DECLARE_CONST(TWLG_FRENCH_SWISS);
	DECLARE_CONST(TWLG_GERMAN);
	DECLARE_CONST(TWLG_GERMAN_AUSTRIAN);
	DECLARE_CONST(TWLG_GERMAN_LUXEMBOURG);
	DECLARE_CONST(TWLG_GERMAN_LIECHTENSTEIN);
	DECLARE_CONST(TWLG_GERMAN_SWISS);
	DECLARE_CONST(TWLG_GREEK);
	DECLARE_CONST(TWLG_HEBREW);
	DECLARE_CONST(TWLG_HUNGARIAN);
	DECLARE_CONST(TWLG_ICELANDIC);
	DECLARE_CONST(TWLG_INDONESIAN);
	DECLARE_CONST(TWLG_ITALIAN);
	DECLARE_CONST(TWLG_ITALIAN_SWISS);
	DECLARE_CONST(TWLG_JAPANESE);
	DECLARE_CONST(TWLG_KOREAN);
	DECLARE_CONST(TWLG_KOREAN_JOHAB);
	DECLARE_CONST(TWLG_LATVIAN);
	DECLARE_CONST(TWLG_LITHUANIAN);
	DECLARE_CONST(TWLG_NORWEGIAN);
	DECLARE_CONST(TWLG_NORWEGIAN_BOKMAL);
	DECLARE_CONST(TWLG_NORWEGIAN_NYNORSK);
	DECLARE_CONST(TWLG_POLISH);
	DECLARE_CONST(TWLG_PORTUGUESE);
	DECLARE_CONST(TWLG_PORTUGUESE_BRAZIL);
	DECLARE_CONST(TWLG_ROMANIAN);
	DECLARE_CONST(TWLG_RUSSIAN);
	DECLARE_CONST(TWLG_SERBIAN_LATIN);
	DECLARE_CONST(TWLG_SLOVAK);
	DECLARE_CONST(TWLG_SLOVENIAN);
	DECLARE_CONST(TWLG_SPANISH);
	DECLARE_CONST(TWLG_SPANISH_MEXICAN);
	DECLARE_CONST(TWLG_SPANISH_MODERN);
	DECLARE_CONST(TWLG_SWEDISH);
	DECLARE_CONST(TWLG_THAI);
	DECLARE_CONST(TWLG_TURKISH);
	DECLARE_CONST(TWLG_UKRANIAN);
	DECLARE_CONST(TWLG_ASSAMESE);
	DECLARE_CONST(TWLG_BENGALI);
	DECLARE_CONST(TWLG_BIHARI);
	DECLARE_CONST(TWLG_BODO);
	DECLARE_CONST(TWLG_DOGRI);
	DECLARE_CONST(TWLG_GUJARATI);
	DECLARE_CONST(TWLG_HARYANVI);
	DECLARE_CONST(TWLG_HINDI);
	DECLARE_CONST(TWLG_KANNADA);
	DECLARE_CONST(TWLG_KASHMIRI);
	DECLARE_CONST(TWLG_MALAYALAM);
	DECLARE_CONST(TWLG_MARATHI);
	DECLARE_CONST(TWLG_MARWARI);
	DECLARE_CONST(TWLG_MEGHALAYAN);
	DECLARE_CONST(TWLG_MIZO);
	DECLARE_CONST(TWLG_NAGA);
	DECLARE_CONST(TWLG_ORISSI);
	DECLARE_CONST(TWLG_PUNJABI);
	DECLARE_CONST(TWLG_PUSHTU);
	DECLARE_CONST(TWLG_SERBIAN_CYRILLIC);
	DECLARE_CONST(TWLG_SIKKIMI);
	DECLARE_CONST(TWLG_SWEDISH_FINLAND);
	DECLARE_CONST(TWLG_TAMIL);
	DECLARE_CONST(TWLG_TELUGU);
	DECLARE_CONST(TWLG_TRIPURI);
	DECLARE_CONST(TWLG_URDU);
	DECLARE_CONST(TWLG_VIETNAMESE);

	DECLARE_CONST(DG_CONTROL);
	DECLARE_CONST(DG_IMAGE);
	DECLARE_CONST(DG_AUDIO);

	DECLARE_CONST(DAT_NULL);
	DECLARE_CONST(DAT_CUSTOMBASE);
	DECLARE_CONST(DAT_CAPABILITY);
	DECLARE_CONST(DAT_EVENT);
	DECLARE_CONST(DAT_IDENTITY);
	DECLARE_CONST(DAT_PARENT);
	DECLARE_CONST(DAT_PENDINGXFERS);
	DECLARE_CONST(DAT_SETUPMEMXFER);
	DECLARE_CONST(DAT_SETUPFILEXFER);
	DECLARE_CONST(DAT_STATUS);
	DECLARE_CONST(DAT_USERINTERFACE);
	DECLARE_CONST(DAT_XFERGROUP);
	DECLARE_CONST(DAT_TWUNKIDENTITY);
	DECLARE_CONST(DAT_CUSTOMDSDATA);
	DECLARE_CONST(DAT_DEVICEEVENT);
	DECLARE_CONST(DAT_FILESYSTEM);
	DECLARE_CONST(DAT_PASSTHRU);
	DECLARE_CONST(DAT_IMAGEINFO);
	DECLARE_CONST(DAT_IMAGELAYOUT);
	DECLARE_CONST(DAT_IMAGEMEMXFER);
	DECLARE_CONST(DAT_IMAGENATIVEXFER);
	DECLARE_CONST(DAT_IMAGEFILEXFER);
	DECLARE_CONST(DAT_CIECOLOR);
	DECLARE_CONST(DAT_GRAYRESPONSE);
	DECLARE_CONST(DAT_RGBRESPONSE);
	DECLARE_CONST(DAT_JPEGCOMPRESSION);
	DECLARE_CONST(DAT_PALETTE8);
	DECLARE_CONST(DAT_EXTIMAGEINFO);
	DECLARE_CONST(DAT_AUDIOFILEXFER);
	DECLARE_CONST(DAT_AUDIOINFO);
	DECLARE_CONST(DAT_AUDIONATIVEXFER);

	DECLARE_CONST(MSG_NULL);
	DECLARE_CONST(MSG_CUSTOMBASE);
	DECLARE_CONST(MSG_GET);
	DECLARE_CONST(MSG_GETCURRENT);
	DECLARE_CONST(MSG_GETDEFAULT);
	DECLARE_CONST(MSG_GETFIRST);
	DECLARE_CONST(MSG_GETNEXT);
	DECLARE_CONST(MSG_SET);
	DECLARE_CONST(MSG_RESET);
	DECLARE_CONST(MSG_QUERYSUPPORT);
	DECLARE_CONST(MSG_XFERREADY);
	DECLARE_CONST(MSG_CLOSEDSREQ);
	DECLARE_CONST(MSG_CLOSEDSOK);
	DECLARE_CONST(MSG_DEVICEEVENT);
	DECLARE_CONST(MSG_CHECKSTATUS);
	DECLARE_CONST(MSG_OPENDSM);
	DECLARE_CONST(MSG_CLOSEDSM);
	DECLARE_CONST(MSG_OPENDS);
	DECLARE_CONST(MSG_CLOSEDS);
	DECLARE_CONST(MSG_USERSELECT);
	DECLARE_CONST(MSG_DISABLEDS);
	DECLARE_CONST(MSG_ENABLEDS);
	DECLARE_CONST(MSG_ENABLEDSUIONLY);
	DECLARE_CONST(MSG_PROCESSEVENT);
	DECLARE_CONST(MSG_ENDXFER);
	DECLARE_CONST(MSG_CHANGEDIRECTORY);
	DECLARE_CONST(MSG_CREATEDIRECTORY);
	DECLARE_CONST(MSG_DELETE);
	DECLARE_CONST(MSG_FORMATMEDIA);
	DECLARE_CONST(MSG_GETCLOSE);
	DECLARE_CONST(MSG_GETFIRSTFILE);
	DECLARE_CONST(MSG_GETINFO);
	DECLARE_CONST(MSG_GETNEXTFILE);
	DECLARE_CONST(MSG_RENAME);
	DECLARE_CONST(MSG_PASSTHRU);

	DECLARE_CONST(CAP_CUSTOMBASE);
	DECLARE_CONST(CAP_XFERCOUNT);

	DECLARE_CONST(ICAP_COMPRESSION);
	DECLARE_CONST(ICAP_PIXELTYPE);
	DECLARE_CONST(ICAP_UNITS);
	DECLARE_CONST(ICAP_XFERMECH);

	DECLARE_CONST(CAP_AUTHOR);
	DECLARE_CONST(CAP_CAPTION);
	DECLARE_CONST(CAP_FEEDERENABLED);
	DECLARE_CONST(CAP_FEEDERLOADED);
	DECLARE_CONST(CAP_TIMEDATE);
	DECLARE_CONST(CAP_SUPPORTEDCAPS);
	DECLARE_CONST(CAP_EXTENDEDCAPS);
	DECLARE_CONST(CAP_AUTOFEED);
	DECLARE_CONST(CAP_CLEARPAGE);
	DECLARE_CONST(CAP_FEEDPAGE);
	DECLARE_CONST(CAP_REWINDPAGE);
	DECLARE_CONST(CAP_INDICATORS);
	DECLARE_CONST(CAP_SUPPORTEDCAPSEXT);
	DECLARE_CONST(CAP_PAPERDETECTABLE);
	DECLARE_CONST(CAP_UICONTROLLABLE);
	DECLARE_CONST(CAP_DEVICEONLINE);
	DECLARE_CONST(CAP_AUTOSCAN);
	DECLARE_CONST(CAP_THUMBNAILSENABLED);
	DECLARE_CONST(CAP_DUPLEX);
	DECLARE_CONST(CAP_DUPLEXENABLED);
	DECLARE_CONST(CAP_ENABLEDSUIONLY);
	DECLARE_CONST(CAP_CUSTOMDSDATA);
	DECLARE_CONST(CAP_ENDORSER);
	DECLARE_CONST(CAP_JOBCONTROL);
	DECLARE_CONST(CAP_ALARMS);
	DECLARE_CONST(CAP_ALARMVOLUME);
	DECLARE_CONST(CAP_AUTOMATICCAPTURE);
	DECLARE_CONST(CAP_TIMEBEFOREFIRSTCAPTURE);
	DECLARE_CONST(CAP_TIMEBETWEENCAPTURES);
	DECLARE_CONST(CAP_CLEARBUFFERS);
	DECLARE_CONST(CAP_MAXBATCHBUFFERS);
	DECLARE_CONST(CAP_DEVICETIMEDATE);
	DECLARE_CONST(CAP_POWERSUPPLY);
	DECLARE_CONST(CAP_CAMERAPREVIEWUI);
	DECLARE_CONST(CAP_DEVICEEVENT);
#if defined(CAP_PAGEMULTIPLEACQUIRE)
	DECLARE_CONST(CAP_PAGEMULTIPLEACQUIRE);
#endif
	DECLARE_CONST(CAP_SERIALNUMBER);
#if (TWON_PROTCOLMAJOR == 1 && TWON_PROTOCOLMINOR < 8)
    // There is an error in the declaration of this value in the twain.h file.
	DECLARE_CONST(CAP_FILESYSTEM);
#endif
	DECLARE_CONST(CAP_PRINTER);
	DECLARE_CONST(CAP_PRINTERENABLED);
	DECLARE_CONST(CAP_PRINTERINDEX);
	DECLARE_CONST(CAP_PRINTERMODE);
	DECLARE_CONST(CAP_PRINTERSTRING);
	DECLARE_CONST(CAP_PRINTERSUFFIX);
	DECLARE_CONST(CAP_LANGUAGE);
	DECLARE_CONST(CAP_FEEDERALIGNMENT);
	DECLARE_CONST(CAP_FEEDERORDER);
#if defined(CAP_PAPERBINDING)
	DECLARE_CONST(CAP_PAPERBINDING);
#endif
	DECLARE_CONST(CAP_REACQUIREALLOWED);
#if defined(CAP_PASSTHRU)
	DECLARE_CONST(CAP_PASSTHRU);
#endif
	DECLARE_CONST(CAP_BATTERYMINUTES);
	DECLARE_CONST(CAP_BATTERYPERCENTAGE);
#if defined(CAP_POWERDOWNTIME)
	DECLARE_CONST(CAP_POWERDOWNTIME);
#endif

#if defined(CAP_CAMERASIDE)
    DECLARE_CONST(CAP_CAMERASIDE);
#endif
#if defined(CAP_SEGMENTED)
    DECLARE_CONST(CAP_SEGMENTED);
#endif
#if defined(CAP_CAMERAENABLED)
    DECLARE_CONST(CAP_CAMERAENABLED);
#endif
#if defined(CAP_CAMERAORDER)
    DECLARE_CONST(CAP_CAMERAORDER);
#endif
#if defined(CAP_MICRENABLED)
    DECLARE_CONST(CAP_MICRENABLED);
#endif
#if defined(CAP_FEEDERPREP)
    DECLARE_CONST(CAP_FEEDERPREP);
#endif
#if defined(CAP_FEEDERPOCKET)
    DECLARE_CONST(CAP_FEEDERPOCKET);
#endif
#if defined(CAP_AUTOMATICSENSEMEDIUM)
    DECLARE_CONST(CAP_AUTOMATICSENSEMEDIUM);
#endif
#if defined(CAP_CUSTOMINTERFACEGUID)
    DECLARE_CONST(CAP_CUSTOMINTERFACEGUID);
#endif

	DECLARE_CONST(ICAP_AUTOBRIGHT);
	DECLARE_CONST(ICAP_BRIGHTNESS);
	DECLARE_CONST(ICAP_CONTRAST);
	DECLARE_CONST(ICAP_CUSTHALFTONE);
	DECLARE_CONST(ICAP_EXPOSURETIME);
	DECLARE_CONST(ICAP_FILTER);
	DECLARE_CONST(ICAP_FLASHUSED);
	DECLARE_CONST(ICAP_GAMMA);
	DECLARE_CONST(ICAP_HALFTONES);
	DECLARE_CONST(ICAP_HIGHLIGHT);
	DECLARE_CONST(ICAP_IMAGEFILEFORMAT);
	DECLARE_CONST(ICAP_LAMPSTATE);
	DECLARE_CONST(ICAP_LIGHTSOURCE);
	DECLARE_CONST(ICAP_ORIENTATION);
	DECLARE_CONST(ICAP_PHYSICALWIDTH);
	DECLARE_CONST(ICAP_PHYSICALHEIGHT);
	DECLARE_CONST(ICAP_SHADOW);
	DECLARE_CONST(ICAP_FRAMES);
	DECLARE_CONST(ICAP_XNATIVERESOLUTION);
	DECLARE_CONST(ICAP_YNATIVERESOLUTION);
	DECLARE_CONST(ICAP_XRESOLUTION);
	DECLARE_CONST(ICAP_YRESOLUTION);
	DECLARE_CONST(ICAP_MAXFRAMES);
	DECLARE_CONST(ICAP_TILES);
	DECLARE_CONST(ICAP_BITORDER);
	DECLARE_CONST(ICAP_CCITTKFACTOR);
	DECLARE_CONST(ICAP_LIGHTPATH);
	DECLARE_CONST(ICAP_PIXELFLAVOR);
	DECLARE_CONST(ICAP_PLANARCHUNKY);
	DECLARE_CONST(ICAP_ROTATION);
	DECLARE_CONST(ICAP_SUPPORTEDSIZES);
	DECLARE_CONST(ICAP_THRESHOLD);
	DECLARE_CONST(ICAP_XSCALING);
	DECLARE_CONST(ICAP_YSCALING);
	DECLARE_CONST(ICAP_BITORDERCODES);
	DECLARE_CONST(ICAP_PIXELFLAVORCODES);
	DECLARE_CONST(ICAP_JPEGPIXELTYPE);
	DECLARE_CONST(ICAP_TIMEFILL);
	DECLARE_CONST(ICAP_BITDEPTH);
	DECLARE_CONST(ICAP_BITDEPTHREDUCTION);
	DECLARE_CONST(ICAP_UNDEFINEDIMAGESIZE);
	DECLARE_CONST(ICAP_IMAGEDATASET);
	DECLARE_CONST(ICAP_EXTIMAGEINFO);
	DECLARE_CONST(ICAP_MINIMUMHEIGHT);
	DECLARE_CONST(ICAP_MINIMUMWIDTH);
	DECLARE_CONST(ICAP_AUTODISCARDBLANKPAGES);
	DECLARE_CONST(ICAP_FLIPROTATION);
	DECLARE_CONST(ICAP_BARCODEDETECTIONENABLED);
	DECLARE_CONST(ICAP_SUPPORTEDBARCODETYPES);
	DECLARE_CONST(ICAP_BARCODEMAXSEARCHPRIORITIES);
	DECLARE_CONST(ICAP_BARCODESEARCHPRIORITIES);
	DECLARE_CONST(ICAP_BARCODESEARCHMODE);
	DECLARE_CONST(ICAP_BARCODEMAXRETRIES);
	DECLARE_CONST(ICAP_BARCODETIMEOUT);
	DECLARE_CONST(ICAP_ZOOMFACTOR);
	DECLARE_CONST(ICAP_PATCHCODEDETECTIONENABLED);
	DECLARE_CONST(ICAP_SUPPORTEDPATCHCODETYPES);
	DECLARE_CONST(ICAP_PATCHCODEMAXSEARCHPRIORITIES);
	DECLARE_CONST(ICAP_PATCHCODESEARCHPRIORITIES);
	DECLARE_CONST(ICAP_PATCHCODESEARCHMODE);
	DECLARE_CONST(ICAP_PATCHCODEMAXRETRIES);
	DECLARE_CONST(ICAP_PATCHCODETIMEOUT);
	DECLARE_CONST(ICAP_FLASHUSED2);
	DECLARE_CONST(ICAP_IMAGEFILTER);
	DECLARE_CONST(ICAP_NOISEFILTER);
	DECLARE_CONST(ICAP_OVERSCAN);
	DECLARE_CONST(ICAP_AUTOMATICBORDERDETECTION);
	DECLARE_CONST(ICAP_AUTOMATICDESKEW);
	DECLARE_CONST(ICAP_AUTOMATICROTATE);

#if defined(ICAP_JPEGQUALITY)
    DECLARE_CONST(ICAP_JPEGQUALITY);
#endif
#if defined(ICAP_FEEDERTYPE)
    DECLARE_CONST(ICAP_FEEDERTYPE);
#endif
#if defined(ICAP_ICCPROFILE)
    DECLARE_CONST(ICAP_ICCPROFILE);
#endif
#if defined(ICAP_AUTOSIZE)
    DECLARE_CONST(ICAP_AUTOSIZE);
#endif
#if defined(ICAP_AUTOMATICCROPUSESFRAME)
    DECLARE_CONST(ICAP_AUTOMATICCROPUSESFRAME);
#endif
#if defined(ICAP_AUTOMATICLENGTHDETECTION)
    DECLARE_CONST(ICAP_AUTOMATICLENGTHDETECTION);
#endif
#if defined(ICAP_AUTOMATICCOLORENABLED)
    DECLARE_CONST(ICAP_AUTOMATICCOLORENABLED);
#endif
#if defined(ICAP_AUTOMATICCOLORNONCOLORPIXELTYPE)
    DECLARE_CONST(ICAP_AUTOMATICCOLORNONCOLORPIXELTYPE);
#endif
#if defined(ICAP_COLORMANAGEMENTENABLED)
    DECLARE_CONST(ICAP_COLORMANAGEMENTENABLED);
#endif
#if defined(ICAP_IMAGEMERGE)
    DECLARE_CONST(ICAP_IMAGEMERGE);
#endif
#if defined(ICAP_IMAGEMERGEHEIGHTTHRESHOLD)
    DECLARE_CONST(ICAP_IMAGEMERGEHEIGHTTHRESHOLD);
#endif
#if defined(ICAP_SUPPORTEDEXTIMAGEINFO )
    DECLARE_CONST(ICAP_SUPPORTEDEXTIMAGEINFO);
#endif

#if defined(ACAP_AUDIOFILEFORMAT)
	DECLARE_CONST(ACAP_AUDIOFILEFORMAT);
#endif
	DECLARE_CONST(ACAP_XFERMECH);

	DECLARE_CONST(TWEI_BARCODEX);
	DECLARE_CONST(TWEI_BARCODEY);
	DECLARE_CONST(TWEI_BARCODETEXT);
	DECLARE_CONST(TWEI_BARCODETYPE);
	DECLARE_CONST(TWEI_DESHADETOP);
	DECLARE_CONST(TWEI_DESHADELEFT);
	DECLARE_CONST(TWEI_DESHADEHEIGHT);
	DECLARE_CONST(TWEI_DESHADEWIDTH);
	DECLARE_CONST(TWEI_DESHADESIZE);
	DECLARE_CONST(TWEI_SPECKLESREMOVED);
	DECLARE_CONST(TWEI_HORZLINEXCOORD);
	DECLARE_CONST(TWEI_HORZLINEYCOORD);
	DECLARE_CONST(TWEI_HORZLINELENGTH);
	DECLARE_CONST(TWEI_HORZLINETHICKNESS);
	DECLARE_CONST(TWEI_VERTLINEXCOORD);
	DECLARE_CONST(TWEI_VERTLINEYCOORD);
	DECLARE_CONST(TWEI_VERTLINELENGTH);
	DECLARE_CONST(TWEI_VERTLINETHICKNESS);
	DECLARE_CONST(TWEI_PATCHCODE);
	DECLARE_CONST(TWEI_ENDORSEDTEXT);
	DECLARE_CONST(TWEI_FORMCONFIDENCE);
	DECLARE_CONST(TWEI_FORMTEMPLATEMATCH);
	DECLARE_CONST(TWEI_FORMTEMPLATEPAGEMATCH);
	DECLARE_CONST(TWEI_FORMHORZDOCOFFSET);
	DECLARE_CONST(TWEI_FORMVERTDOCOFFSET);
	DECLARE_CONST(TWEI_BARCODECOUNT);
	DECLARE_CONST(TWEI_BARCODECONFIDENCE);
	DECLARE_CONST(TWEI_BARCODEROTATION);
	DECLARE_CONST(TWEI_BARCODETEXTLENGTH);
	DECLARE_CONST(TWEI_DESHADECOUNT);
	DECLARE_CONST(TWEI_DESHADEBLACKCOUNTOLD);
	DECLARE_CONST(TWEI_DESHADEBLACKCOUNTNEW);
	DECLARE_CONST(TWEI_DESHADEBLACKRLMIN);
	DECLARE_CONST(TWEI_DESHADEBLACKRLMAX);
	DECLARE_CONST(TWEI_DESHADEWHITECOUNTOLD);
	DECLARE_CONST(TWEI_DESHADEWHITECOUNTNEW);
	DECLARE_CONST(TWEI_DESHADEWHITERLMIN);
	DECLARE_CONST(TWEI_DESHADEWHITERLAVE);
	DECLARE_CONST(TWEI_DESHADEWHITERLMAX);
	DECLARE_CONST(TWEI_BLACKSPECKLESREMOVED);
	DECLARE_CONST(TWEI_WHITESPECKLESREMOVED);
	DECLARE_CONST(TWEI_HORZLINECOUNT);
	DECLARE_CONST(TWEI_VERTLINECOUNT);
	DECLARE_CONST(TWEI_DESKEWSTATUS);
	DECLARE_CONST(TWEI_SKEWORIGINALANGLE);
	DECLARE_CONST(TWEI_SKEWFINALANGLE);
	DECLARE_CONST(TWEI_SKEWCONFIDENCE);
	DECLARE_CONST(TWEI_SKEWWINDOWX1);
	DECLARE_CONST(TWEI_SKEWWINDOWY1);
	DECLARE_CONST(TWEI_SKEWWINDOWX2);
	DECLARE_CONST(TWEI_SKEWWINDOWY2);
	DECLARE_CONST(TWEI_SKEWWINDOWX3);
	DECLARE_CONST(TWEI_SKEWWINDOWY3);
	DECLARE_CONST(TWEI_SKEWWINDOWX4);
	DECLARE_CONST(TWEI_SKEWWINDOWY4);

#if defined(TWEI_BOOKNAME)
    DECLARE_CONST(TWEI_BOOKNAME);
#endif
#if defined(TWEI_CHAPTERNUMBER)
    DECLARE_CONST(TWEI_CHAPTERNUMBER);
#endif
#if defined(TWEI_DOCUMENTNUMBER)
    DECLARE_CONST(TWEI_DOCUMENTNUMBER);
#endif
#if defined(TWEI_PAGENUMBER)
    DECLARE_CONST(TWEI_PAGENUMBER);
#endif
#if defined(TWEI_CAMERA)
    DECLARE_CONST(TWEI_CAMERA);
#endif
#if defined(TWEI_FRAMENUMBER)
    DECLARE_CONST(TWEI_FRAMENUMBER);
#endif
#if defined(TWEI_FRAME)
    DECLARE_CONST(TWEI_FRAME);
#endif
#if defined(TWEI_PIXELFLAVOR)
    DECLARE_CONST(TWEI_PIXELFLAVOR);
#endif
#if defined(TWEI_ICCPROFILE)
    DECLARE_CONST(TWEI_ICCPROFILE);
#endif
#if defined(TWEI_LASTSEGMENT)
    DECLARE_CONST(TWEI_LASTSEGMENT);
#endif
#if defined(TWEI_SEGMENTNUMBER)
    DECLARE_CONST(TWEI_SEGMENTNUMBER);
#endif
#if defined(TWEI_MAGDATA)
    DECLARE_CONST(TWEI_MAGDATA);
#endif
#if defined(TWEI_MAGTYPE)
    DECLARE_CONST(TWEI_MAGTYPE);
#endif
#if defined(TWEI_PAGESIDE)
    DECLARE_CONST(TWEI_PAGESIDE);
#endif
#if defined(TWEI_FILESYSTEMSOURCE)
    DECLARE_CONST(TWEI_FILESYSTEMSOURCE);
#endif
#if defined(TWEI_IMAGEMERGED)
    DECLARE_CONST(TWEI_IMAGEMERGED);
#endif
#if defined(TWEI_MAGDATALENGTH)
    DECLARE_CONST(TWEI_MAGDATALENGTH);
#endif

	DECLARE_CONST(TWEJ_NONE);
	DECLARE_CONST(TWEJ_MIDSEPARATOR);
	DECLARE_CONST(TWEJ_PATCH1);
	DECLARE_CONST(TWEJ_PATCH2);
	DECLARE_CONST(TWEJ_PATCH3);
	DECLARE_CONST(TWEJ_PATCH4);
	DECLARE_CONST(TWEJ_PATCH6);
	DECLARE_CONST(TWEJ_PATCHT);

	DECLARE_CONST(TWRC_CUSTOMBASE);
	DECLARE_CONST(TWRC_SUCCESS);
	DECLARE_CONST(TWRC_FAILURE);
	DECLARE_CONST(TWRC_CHECKSTATUS);
	DECLARE_CONST(TWRC_CANCEL);
	DECLARE_CONST(TWRC_DSEVENT);
	DECLARE_CONST(TWRC_NOTDSEVENT);
	DECLARE_CONST(TWRC_XFERDONE);
	DECLARE_CONST(TWRC_ENDOFLIST);
	DECLARE_CONST(TWRC_INFONOTSUPPORTED);
	DECLARE_CONST(TWRC_DATANOTAVAILABLE);

	DECLARE_CONST(TWCC_CUSTOMBASE);
	DECLARE_CONST(TWCC_SUCCESS);
	DECLARE_CONST(TWCC_BUMMER);
	DECLARE_CONST(TWCC_LOWMEMORY);
	DECLARE_CONST(TWCC_NODS);
	DECLARE_CONST(TWCC_MAXCONNECTIONS);
	DECLARE_CONST(TWCC_OPERATIONERROR);
	DECLARE_CONST(TWCC_BADCAP);
	DECLARE_CONST(TWCC_BADPROTOCOL);
	DECLARE_CONST(TWCC_BADVALUE);
	DECLARE_CONST(TWCC_SEQERROR);
	DECLARE_CONST(TWCC_BADDEST);
	DECLARE_CONST(TWCC_CAPUNSUPPORTED);
	DECLARE_CONST(TWCC_CAPBADOPERATION);
	DECLARE_CONST(TWCC_CAPSEQERROR);
	DECLARE_CONST(TWCC_DENIED);
	DECLARE_CONST(TWCC_FILEEXISTS);
	DECLARE_CONST(TWCC_FILENOTFOUND);
	DECLARE_CONST(TWCC_NOTEMPTY);
	DECLARE_CONST(TWCC_PAPERJAM);
	DECLARE_CONST(TWCC_PAPERDOUBLEFEED);
	DECLARE_CONST(TWCC_FILEWRITEERROR);
	DECLARE_CONST(TWCC_CHECKDEVICEONLINE);

#if defined(TWCC_DAMAGEDCORNER)
    DECLARE_CONST(TWCC_DAMAGEDCORNER);
#endif
#if defined(TWCC_FOCUSERROR)
    DECLARE_CONST(TWCC_FOCUSERROR);
#endif
#if defined(TWCC_DOCTOOLIGHT)
    DECLARE_CONST(TWCC_DOCTOOLIGHT);
#endif
#if defined(TWCC_DOCTOODARK)
    DECLARE_CONST(TWCC_DOCTOODARK);
#endif
#if defined(TWCC_NOMEDIA)
    DECLARE_CONST(TWCC_NOMEDIA);
#endif


	DECLARE_CONST(TWQC_GET);
	DECLARE_CONST(TWQC_SET);
	DECLARE_CONST(TWQC_GETDEFAULT);
	DECLARE_CONST(TWQC_GETCURRENT);
	DECLARE_CONST(TWQC_RESET);

	DeclareWindowClass();

}

// The twain FIX32 format is a fixed precision decimal
// number stored as two 16bit integers. 
// These functions convert between a floating point
// number and the fixed point numbers.
static TW_FIX32 FloatToFix32 (double floater)
{
	TW_FIX32 Fix32_value;
	TW_INT32 value = (TW_INT32) (floater * 65536.0 + 0.5);
	Fix32_value.Whole = (short)((value >> 16) &0xFFFFL);
	Fix32_value.Frac = (short)(value & 0x0000ffffL);
	return (Fix32_value);
}

static double Fix32ToFloat(TW_FIX32 *pFix32)
{
	char szBuffer[30];
	sprintf(szBuffer, "%d.%d", pFix32->Whole, pFix32->Frac);
	return atof(szBuffer);
}


//-------------------------- Message Loop and Pseudo-Window Control
//
//	The twain interface passes messages back to the application
//	via the standard windows messaging system. In order to get
//	these messages in the twainmodule, we setup a hidden window,
//	(one per SourceManger object).
//
//	Then when messages occur, we can send them through to the
//	twain API, as per the twain specification.
//
//	This saves the pain of hacking the windows toolkits specifically,
//	i.e. we don't have to edit the wxWindows / Tk code.
//

static char *szClassName = "PythonTwainPseudoWindow";

static LRESULT APIENTRY 
PseudoWndProc(HWND hWnd, WORD wMsg, DWORD wParam, LONG lParam)
{
	int i;

#if TRACE
printf("PseudoWndProc(0x%lx, 0x%x, 0x%lx, 0x%lx), thread %d\n", 
	   hWnd, wMsg, wParam, lParam, GetCurrentThreadId());
#endif 


	switch(wMsg)
	{
	case WM_NCDESTROY:
	case WM_DESTROY:
		// If we are not executing the destructor, we need to kill the
		// source manager. This can occur if the user shuts a program
		// by deleting the window, rather than allowing the program to
		// delete the SourceManager object.
		for (i=0; i< MAX_SM_OBJECTS; i++) {
			if (AllSMObjects[i] && AllSMObjects[i]->hWndPseudo == hWnd) {
				kill_SourceManager(AllSMObjects[i], FALSE);
				break;
			}
		}
#if TRACE
printf("PseudoWndProc returning, i = %d\n", i);
#endif 
		return 0L;
	case WM_NCCREATE:
		return 1L;
	case WM_ACTIVATE:
		// When the window is activated, we must activate the application
		if (LOWORD(wParam)) {
			for (i=0; i< MAX_SM_OBJECTS; i++)
				if (AllSMObjects[i] && AllSMObjects[i]->hWndPseudo == hWnd)
					break;
			if (i == MAX_SM_OBJECTS) 
				break; // sanity problem
			if (AllSMObjects[i]->hWnd)
				SetActiveWindow(AllSMObjects[i]->hWnd);
		}
		return 0L;
	default:

		for (i=0; i< MAX_SD_OBJECTS; i++)
			if (AllSDObjects[i] && AllSDObjects[i]->pSM->hWndPseudo == hWnd)
				break;

		if (i == MAX_SD_OBJECTS) 
			break; // sanity problem

		//	Pass everything else through to Source Event Handler
		return Source_ProcessEventImpl(AllSDObjects[i], wMsg, wParam, lParam);
	}
	// There is now only ever going to be one window, and the
	// source manager does not need to intercept the messages (only the source)
	return DefWindowProc(hWnd, wMsg, wParam, lParam); 
}

static void
DeclareWindowClass ()
{
	//	Declare a windows class which will be used to create
	//	pseudo-windows for each source manager.
	WNDCLASS       wc ;
	long lRv ;

	wc.style         = CS_GLOBALCLASS;
	wc.lpfnWndProc   = (WNDPROC) PseudoWndProc ;
	wc.hInstance     = (HANDLE) GetWindowLong(GetActiveWindow(), GWL_HINSTANCE); //MSDN
	wc.cbClsExtra    = 0;
	wc.cbWndExtra    = 0 ;
	wc.hIcon         = NULL ;
	wc.hCursor       = LoadCursor(NULL, IDC_ARROW) ;
	wc.hbrBackground = GetStockObject(WHITE_BRUSH) ;
	wc.lpszMenuName  = NULL ;
	wc.lpszClassName = szClassName;
	lRv = RegisterClass (&wc);  
}

static HWND 
CreateWindowInstance(HWND hWndParent)
{
	//	Create a window, and return the handle
	HWND rv;
	HANDLE hInstance = (HANDLE) GetWindowLong(hWndParent, GWL_HINSTANCE);

	rv =  CreateWindowEx(
		WS_EX_NOPARENTNOTIFY,      // extended window style
		szClassName,				 // pointer to registered class name
		"PythonPseudoWindow",        // pointer to window name
		WS_DISABLED,             // window style
		1,             // horizontal position of window
		1,             // vertical position of window
		100,           // window width
		100,           // window height
		hWndParent,	   // handle to parent or owner window
		NULL,          // handle to menu, or child-window identifier
		hInstance,     // handle to application instance
		NULL           // pointer to window-creation data
		);

	//	Put the parent back into the foreground
	if (rv && hWndParent)
		SetForegroundWindow(hWndParent);
	return rv;
}

static void 
DestroyWindowInstance(HWND hWnd)
{
	DestroyWindow(hWnd);
}
