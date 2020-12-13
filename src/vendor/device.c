/*++

Copyright (c) 2020 Mario Bãlãnicã. All Rights Reserved.
Copyright (c) Microsoft Corporation. All Rights Reserved.

Module Name:

   device.c

Abstract:

	This file handles device specific operations.

Environment:

	Kernel mode only

--*/

#include "driver.h"  
#include "Device.tmh"
#include <limits.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DeviceQueryDeviceParameters)
#endif

//
// Device registry value names
//
#define STR_REG_BAUDRATE          L"BaudRate"
#define STR_REG_SKIP_FW_DOWNLOAD  L"SkipFwDownload"
#define STR_REG_FW_DIRECTORY      L"FwDirectory"

//
// Default device settings
//
#define DEFAULT_BAUD_RATE         115200
#define DEFAULT_SKIP_FW_DOWNLOAD  0
#define DEFAULT_FW_DIRECTORY      L"\\SystemRoot\\System32\\drivers\\"

typedef struct _DEVICE_CONFIG_PARAMETERS
{
	ULONG           BaudRate;
	ULONG           SkipFwDownload;
	UNICODE_STRING  FwDirectory;
} DEVICE_CONFIG_PARAMETERS, * PDEVICE_CONFIG_PARAMETERS;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONFIG_PARAMETERS, GetDeviceConfigParameters)

//
// HCI helper definitions
//
#define HCI_COMMAND_SUCCESS    0
#define BCM_HCI_MIN_EVENT_SIZE 6

typedef struct _BCM_HCI_VERBOSE_CONFIG
{
	UCHAR   ChipId;
	UCHAR   TargetId;
	USHORT  BuildBase;
	USHORT  BuildNum;
} BCM_HCI_VERBOSE_CONFIG, * PBCM_HCI_VERBOSE_CONFIG;

#define BCM_ENTER_FW_DOWNLOAD_MODE_DELAY_MICROS 50000  // 50 ms
#define BCM_FW_DOWNLOAD_COMPLETE_DELAY_MICROS   250000 // 250 ms

#define BCM_INITIAL_LOCAL_NAME_MAX_LENGTH  15
#define BCM_INITIAL_LOCAL_NAME_PREFIX      L"BCM"
#define BCM_FW_EXTENSION                   L".hcd"

VOID
SleepMicroseconds(
	_In_ ULONG _Time
)
/*++

Routine Description:

	This function delays the execution thread for x microseconds.

Arguments:

	_Time - microseconds to delay

Return Value:

	None

--*/
{
	LARGE_INTEGER Interval;
	Interval.QuadPart = _Time * -10LL;

	KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}

NTSTATUS
AppendStringsToString(
	_Inout_ PUNICODE_STRING   _BaseString,
	_In_    PUNICODE_STRING* _Strings,
	_In_    ULONG             _NumberOfStrings
)
/*++

Routine Description:

	This function appends an array of strings to a string.

Arguments:

	_BaseString - the resulting string

	_Strings - an array of strings to get appended to _BaseString

	_NumberOfStrings

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;

	if (_BaseString == NULL || _Strings == NULL || _NumberOfStrings == 0)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

	for (ULONG Index = 0; Index < _NumberOfStrings; ++Index)
	{
		Status = RtlAppendUnicodeStringToString(_BaseString, _Strings[Index]);

		if (!NT_SUCCESS(Status))
			goto Done;
	}

Done:
	return Status;
}

NTSTATUS
BuildFirmwarePath(
	_Inout_ PUNICODE_STRING _Path,
	_In_    PUNICODE_STRING _PathDirectory,
	_In_    PUNICODE_STRING _LocalName
)
/*++

Routine Description:

	This function builds the full path to the HCD firmware.

Arguments:

	_Path - the resulting path

	_PathDirectory - directory where the firmware is located (must end with a backslash)

	_LocalName - the name of the chip (will be appended to _PathDirectory)

Return Value:

	NTSTATUS

	Note: in case of success, a memory buffer that holds the path string is allocated.
		  Call ExFreePool on the Buffer member to free it.

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING FirmwareExt;
	ULONG FirmwarePathMaxLength;
	PWCHAR FirmwarePathBuffer;
	PUNICODE_STRING PathComponents[3];

	RtlUnicodeStringInit(&FirmwareExt, BCM_FW_EXTENSION);

	PathComponents[0] = _PathDirectory;
	PathComponents[1] = _LocalName;
	PathComponents[2] = &FirmwareExt;

	FirmwarePathMaxLength = _PathDirectory->Length
		+ _LocalName->MaximumLength
		+ FirmwareExt.Length;

	if (FirmwarePathMaxLength > USHRT_MAX)
	{
		Status = STATUS_NAME_TOO_LONG;
		goto Done;
	}

	FirmwarePathBuffer = ExAllocatePool(NonPagedPool, FirmwarePathMaxLength);

	if (FirmwarePathBuffer == NULL)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Done;
	}

	RtlInitEmptyUnicodeString(_Path, FirmwarePathBuffer, (USHORT)FirmwarePathMaxLength);

	Status = AppendStringsToString(_Path,
		PathComponents,
		sizeof(PathComponents) / sizeof(PUNICODE_STRING));

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(FirmwarePathBuffer);
		goto Done;
	}

Done:
	return Status;
}

NTSTATUS
SendIoctlToIoTargetSync(
	_In_        WDFIOTARGET _IoTargetSerial,
	_In_opt_    WDFREQUEST  _ReusableRequest,
	_In_        ULONG       _IoControlCode,
	_In_opt_    PVOID       _InputBuffer,
	_In_opt_    ULONG       _InputBufferLength,
	_Inout_opt_ PVOID       _OutputBuffer,
	_In_opt_    ULONG       _OutputBufferLength,
	_Out_opt_   PULONG_PTR  _BytesReturned
)
/*++

Routine Description:

	This function synchronously sends an IOCTL to an I/O target with timeout.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_IoControlCode - the IOCTL code

	_InputBuffer - (optional)
	_InputBufferLength - (optional) the size of the _InputBuffer

	_OutputBuffer - (optional)
	_OutputBufferLength - (optional) the size of the _OutputBuffer

	_BytesReturned - (optional) the total count of bytes returned by the device
					 Depending on the device driver, a write operation can be successfully made with 0 bytes returned.

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	WDF_REQUEST_REUSE_PARAMS RequestReuseParams;
	WDF_REQUEST_SEND_OPTIONS RequestOptions;
	WDF_MEMORY_DESCRIPTOR InputMemoryDescriptor;
	WDF_MEMORY_DESCRIPTOR OutputMemoryDescriptor;
	BOOLEAN HasInputBuffer = FALSE;
	BOOLEAN HasOutputBuffer = FALSE;
	ULONG_PTR BytesReturned = 0;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+SendIoctlToIoTargetSync"));

	if (_ReusableRequest != NULL)
	{
		WDF_REQUEST_REUSE_PARAMS_INIT(&RequestReuseParams, WDF_REQUEST_REUSE_NO_FLAGS, STATUS_SUCCESS);
		Status = WdfRequestReuse(_ReusableRequest, &RequestReuseParams);

		if (!NT_SUCCESS(Status))
		{
			DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestReuse failed %!STATUS!", Status));
			goto Done;
		}
	}

	WDF_REQUEST_SEND_OPTIONS_INIT(&RequestOptions, WDF_REQUEST_SEND_OPTION_TIMEOUT);
	WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&RequestOptions, WDF_REL_TIMEOUT_IN_SEC(MAX_WRITE_TIMEOUT_IN_SEC));

	if (_InputBuffer != NULL && _InputBufferLength > 0)
	{
		WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&InputMemoryDescriptor,
			_InputBuffer,
			_InputBufferLength);

		HasInputBuffer = TRUE;
	}

	if (_OutputBuffer != NULL && _OutputBufferLength > 0)
	{
		WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&OutputMemoryDescriptor,
			_OutputBuffer,
			_OutputBufferLength);

		HasOutputBuffer = TRUE;
	}

	Status = WdfIoTargetSendIoctlSynchronously(_IoTargetSerial,
		_ReusableRequest,
		_IoControlCode,
		HasInputBuffer ? &InputMemoryDescriptor : NULL,
		HasOutputBuffer ? &OutputMemoryDescriptor : NULL,
		&RequestOptions,
		&BytesReturned);

	if (NT_SUCCESS(Status))
	{
		DoTrace(LEVEL_INFO, TFLAG_IO, (" WdfIoTargetSendIoctlSynchronously succeeded: %d bytes returned",
			(ULONG)BytesReturned));

		if (_BytesReturned != NULL)
			*_BytesReturned = BytesReturned;
	}
	else
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfIoTargetSendIoctlSynchronously failed %!STATUS!", Status));

Done:
	DoTrace(LEVEL_INFO, TFLAG_IO, ("-SendIoctlToIoTargetSync %!STATUS!", Status));
	return Status;
}

NTSTATUS
WriteToIoTargetSync(
	_In_      WDFIOTARGET _IoTargetSerial,
	_In_opt_  WDFREQUEST  _ReusableRequest,
	_In_      PUCHAR      _Data,
	_In_      ULONG       _Length,
	_Out_opt_ PULONG_PTR  _BytesWritten
)
/*++

Routine Description:

	This function synchronously writes data to an I/O target with timeout.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_Data - input data
	_Length - the size of the input data

	_BytesWritten - (optional) the total count of bytes written to the device

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	WDF_REQUEST_REUSE_PARAMS RequestReuseParams;
	WDF_REQUEST_SEND_OPTIONS RequestOptions;
	WDF_MEMORY_DESCRIPTOR MemoryDescriptor;
	ULONG_PTR  BytesWritten = 0;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+WriteToIoTargetSync"));

	if (_ReusableRequest != NULL)
	{
		WDF_REQUEST_REUSE_PARAMS_INIT(&RequestReuseParams, WDF_REQUEST_REUSE_NO_FLAGS, STATUS_SUCCESS);
		Status = WdfRequestReuse(_ReusableRequest, &RequestReuseParams);

		if (!NT_SUCCESS(Status))
		{
			DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestReuse failed %!STATUS!", Status));
			goto Done;
		}
	}

	WDF_REQUEST_SEND_OPTIONS_INIT(&RequestOptions, WDF_REQUEST_SEND_OPTION_TIMEOUT);
	WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&RequestOptions, WDF_REL_TIMEOUT_IN_SEC(MAX_WRITE_TIMEOUT_IN_SEC));

	WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&MemoryDescriptor,
		(PVOID)_Data,
		_Length);

	Status = WdfIoTargetSendWriteSynchronously(_IoTargetSerial,
		_ReusableRequest,
		&MemoryDescriptor,
		NULL,
		&RequestOptions,
		&BytesWritten);

	if (NT_SUCCESS(Status))
	{
		DoTrace(LEVEL_INFO, TFLAG_IO, (" WdfIoTargetSendWriteSynchronously succeeded: %d bytes sent, %d bytes written",
			_Length, (ULONG)BytesWritten));

		if (_BytesWritten != NULL)
			*_BytesWritten = BytesWritten;
	}
	else
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfIoTargetSendWriteSynchronously failed %!STATUS!", Status));

Done:
	DoTrace(LEVEL_INFO, TFLAG_IO, ("-WriteToIoTargetSync %!STATUS!", Status));
	return Status;
}

NTSTATUS
ReadFromIoTargetSync(
	_In_      WDFIOTARGET _IoTargetSerial,
	_In_opt_  WDFREQUEST  _ReusableRequest,
	_Inout_   PUCHAR      _Data,
	_In_      ULONG       _Length,
	_Out_opt_ PULONG_PTR  _BytesRead
)
/*++

Routine Description:

	This function synchronously reads data from an I/O target with timeout.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_Data - output buffer
	_Length - the size of the output buffer

	_BytesRead - (optional) the total count of bytes read from the device

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	WDF_REQUEST_REUSE_PARAMS RequestReuseParams;
	WDF_REQUEST_SEND_OPTIONS RequestOptions;
	WDF_MEMORY_DESCRIPTOR MemoryDescriptor;
	ULONG_PTR BytesRead = 0;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+ReadFromIoTargetSync"));

	if (_ReusableRequest != NULL)
	{
		WDF_REQUEST_REUSE_PARAMS_INIT(&RequestReuseParams, WDF_REQUEST_REUSE_NO_FLAGS, STATUS_SUCCESS);
		Status = WdfRequestReuse(_ReusableRequest, &RequestReuseParams);

		if (!NT_SUCCESS(Status))
		{
			DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestReuse failed %!STATUS!", Status));
			goto Done;
		}
	}

	WDF_REQUEST_SEND_OPTIONS_INIT(&RequestOptions, WDF_REQUEST_SEND_OPTION_TIMEOUT);
	WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&RequestOptions, WDF_REL_TIMEOUT_IN_SEC(MAX_READ_TIMEOUT_IN_SEC));

	WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&MemoryDescriptor,
		_Data,
		_Length);

	Status = WdfIoTargetSendReadSynchronously(_IoTargetSerial,
		_ReusableRequest,
		&MemoryDescriptor,
		NULL,
		&RequestOptions,
		&BytesRead);

	if (NT_SUCCESS(Status))
	{
		DoTrace(LEVEL_INFO, TFLAG_IO, (" WdfIoTargetSendReadSynchronously succeeded: %d bytes requested, %d bytes received",
			_Length, (ULONG)BytesRead));

		if (_BytesRead != NULL)
			*_BytesRead = BytesRead;
	}
	else
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfIoTargetSendReadSynchronously failed %!STATUS!", Status));

Done:
	DoTrace(LEVEL_INFO, TFLAG_IO, ("-ReadFromIoTargetSync %!STATUS!", Status));
	return Status;
}

NTSTATUS
ReadHciEventSync(
	_In_      WDFIOTARGET _IoTargetSerial,
	_In_opt_  WDFREQUEST  _ReusableRequest,
	_Inout_   PUCHAR      _Data,
	_In_      ULONG       _Length,
	_Out_opt_ PULONG_PTR  _BytesRead
)
/*++

Routine Description:

	This function synchronously reads a HCI event from an I/O target with timeout.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_Data - output buffer
	_Length - the size of the output buffer

	_BytesRead - (optional) the total count of bytes read from the device

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG_PTR BytesRead = 0;
	ULONG BytesCount = 0;
	ULONG ParametersToRead = 0;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+ReadHciEventSync"));

	if (_Length == 0)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

	//
	// 1st byte = packet type
	// Read until we get HciPacketEvent (0x04)
	//
	while (TRUE)
	{
		UCHAR CurrentByte = 0;
		Status = ReadFromIoTargetSync(_IoTargetSerial,
			_ReusableRequest,
			&CurrentByte,
			sizeof(UCHAR),
			NULL);

		if (!NT_SUCCESS(Status))
			goto Done;

		if (CurrentByte == (UCHAR)HciPacketEvent)
			break;
	}

	//
	// Read the next 2 bytes
	// 2nd byte = event code
	// 3rd byte = parameters length
	//
	while (BytesCount < HCI_EVENT_HEADER_SIZE)
	{
		Status = ReadFromIoTargetSync(_IoTargetSerial,
			_ReusableRequest,
			_Data + BytesRead,
			(ULONG)(HCI_EVENT_HEADER_SIZE - BytesRead),
			&BytesRead);

		if (!NT_SUCCESS(Status))
			goto Done;

		BytesCount += (ULONG)BytesRead;
	}

	// Don't read more bytes than requested into the output buffer
	if (_Data[1] < (_Length - HCI_EVENT_HEADER_SIZE))
		ParametersToRead = _Data[1];
	else
	{
		ParametersToRead = _Length - HCI_EVENT_HEADER_SIZE;

		DoTrace(LEVEL_WARNING, TFLAG_IO, (" Warning: output buffer size (%d) is less than the received event total length (%d)",
			_Length, _Data[1] + HCI_EVENT_HEADER_SIZE));
	}

	//
	// Read the parameters
	//
	while ((BytesCount - HCI_EVENT_HEADER_SIZE) < ParametersToRead)
	{
		Status = ReadFromIoTargetSync(_IoTargetSerial,
			_ReusableRequest,
			_Data + BytesCount,
			(ULONG)(ParametersToRead - (BytesCount - HCI_EVENT_HEADER_SIZE)),
			&BytesRead);

		if (!NT_SUCCESS(Status))
			goto Done;

		BytesCount += (ULONG)BytesRead;
	}

	if (_BytesRead != NULL)
		*_BytesRead = BytesCount;

Done:
	DoTrace(LEVEL_INFO, TFLAG_IO, ("-ReadHciEventSync %!STATUS!", Status));
	return Status;
}

NTSTATUS
SendHciCommandSync(
	_In_      WDFIOTARGET _IoTargetSerial,
	_In_opt_  WDFREQUEST  _ReusableRequest,
	_Inout_   PUCHAR      _Data,
	_In_      ULONG       _Length,
	_Out_opt_ PULONG_PTR  _BytesWritten
)
/*++

Routine Description:

	This function synchronously sends a HCI command to an I/O target with timeout.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_Data - input command data
	_Length - the size of the input command data

	_BytesWritten - (optional) the total count of bytes written to the device

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG_PTR BytesWritten = 0;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+SendHciCommandSync"));

	if (_Length == 0)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

	//
	// Send the packet type
	//
	UCHAR PacketType = (UCHAR)HciPacketCommand;
	Status = WriteToIoTargetSync(_IoTargetSerial,
		_ReusableRequest,
		&PacketType,
		sizeof(UCHAR),
		NULL);

	if (!NT_SUCCESS(Status))
		goto Done;

	//
	// Send the command itself
	//
	Status = WriteToIoTargetSync(_IoTargetSerial,
		_ReusableRequest,
		_Data,
		_Length,
		&BytesWritten);

	if (!NT_SUCCESS(Status))
		goto Done;

	if (_BytesWritten != NULL)
		*_BytesWritten = BytesWritten;

Done:
	DoTrace(LEVEL_INFO, TFLAG_IO, ("-SendHciCommandSync %!STATUS!", Status));
	return Status;
}

NTSTATUS
HciVerifyEvent(
	_In_ PUCHAR _CommandData,
	_In_ ULONG  _CommandDataLength,
	_In_ PUCHAR _EventData,
	_In_ ULONG  _EventDataLength
)
/*++

Routine Description:

	This function validates a HCI event depending on the previously sent command.

Arguments:

	_CommandData - the executed command
	_CommandDataLength - the length of the executed command

	_EventData - the received event
	_EventData - the length of the received event

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+HciVerifyEvent"));

	if (!WithinRange(MIN_HCI_CMD_SIZE, _CommandDataLength, MAX_HCI_CMD_SIZE))
	{
		DoTrace(LEVEL_ERROR, TFLAG_HCI, (" _CommandDataLength out of range (%d)", _CommandDataLength));
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

	if (!WithinRange(BCM_HCI_MIN_EVENT_SIZE, _EventDataLength, MAX_HCI_EVENT_SIZE))
	{
		DoTrace(LEVEL_ERROR, TFLAG_HCI, (" _EventDataLength out of range (%d)", _EventDataLength));
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

	DoTrace(LEVEL_INFO, TFLAG_HCI, (" <- HCI EventCode: 0x%x, nRequestedParams: %d, nTotalParams: %d,",
		_EventData[0],
		_EventDataLength - HCI_EVENT_HEADER_SIZE,
		_EventData[1]));

	for (ULONG Index = 0;
		Index < MinToPrint(_EventDataLength - HCI_EVENT_HEADER_SIZE, MAX_EVENT_PARAMS_TO_DISPLAY);
		Index++)
	{
		DoTrace(LEVEL_VERBOSE, TFLAG_HCI, ("    [%d] 0x%.2x",
			Index, _EventData[Index + HCI_EVENT_HEADER_SIZE]));
	}

	//
	// If everything is right, we should get back the command opcode
	// and the completion status
	//
	if (_EventData[3] != _CommandData[0]         // Check LSB (Opcode Command Field)
		|| _EventData[4] != _CommandData[1]      // Check MSB (Opcode Group Field)
		|| _EventData[5] != HCI_COMMAND_SUCCESS)
	{
		DoTrace(LEVEL_ERROR, TFLAG_HCI, (" Bad event parameters!"));
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

Done:
	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-HciVerifyEvent %!STATUS!", Status));
	return Status;
}

NTSTATUS
BcmHciReset(
	_In_     WDFIOTARGET _IoTargetSerial,
	_In_opt_ WDFREQUEST  _ReusableRequest
)
/*++

Routine Description:

	This function performs a HCI reset.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	UCHAR ReadBuffer[MAX_HCI_EVENT_SIZE] = { 0 };
	ULONG_PTR BytesRead = 0;

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+BcmHciReset"));

	UCHAR Command[] = { 0x03, 0x0C, 0x00 };

	Status = SendHciCommandSync(_IoTargetSerial,
		_ReusableRequest,
		Command,
		sizeof(Command),
		NULL
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = ReadHciEventSync(_IoTargetSerial,
		_ReusableRequest,
		ReadBuffer,
		sizeof(ReadBuffer),
		&BytesRead
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = HciVerifyEvent(Command, sizeof(Command), ReadBuffer, (ULONG)BytesRead);

	if (!NT_SUCCESS(Status))
		goto Done;
Done:
	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-BcmHciReset %!STATUS!", Status));
	return Status;
}

NTSTATUS
BcmHciGetVerboseConfig(
	_In_      WDFIOTARGET             _IoTargetSerial,
	_In_opt_  WDFREQUEST              _ReusableRequest,
	_Out_     PBCM_HCI_VERBOSE_CONFIG _VerboseConfig
)
/*++

Routine Description:

	This function gets the vendor-specific verbose config from the Bluetooth device.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_VerboseConfig - returned verbose config

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	UCHAR ReadBuffer[MAX_HCI_EVENT_SIZE] = { 0 };
	ULONG_PTR BytesRead = 0;

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+BcmHciGetVerboseConfig"));

	UCHAR Command[] = { 0x79, 0xfc, 0x00 };

	if (_VerboseConfig == NULL)
	{
		Status = STATUS_INVALID_PARAMETER;
		DoTrace(LEVEL_ERROR, TFLAG_HCI, (" _VerboseConfig is NULL!"));
		goto Done;
	}

	Status = SendHciCommandSync(_IoTargetSerial,
		_ReusableRequest,
		Command,
		sizeof(Command),
		NULL);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = ReadHciEventSync(_IoTargetSerial,
		_ReusableRequest,
		ReadBuffer,
		sizeof(ReadBuffer),
		&BytesRead);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = HciVerifyEvent(Command, sizeof(Command), ReadBuffer, (ULONG)BytesRead);

	if (!NT_SUCCESS(Status))
		goto Done;

	_VerboseConfig->ChipId = ReadBuffer[6];
	_VerboseConfig->TargetId = ReadBuffer[7];
	_VerboseConfig->BuildBase = ReadBuffer[8] | ReadBuffer[9] << 8;
	_VerboseConfig->BuildNum = ReadBuffer[10] | ReadBuffer[11] << 8;

	DoTrace(LEVEL_INFO, TFLAG_HCI, (" ChipId: %d", _VerboseConfig->ChipId));
	DoTrace(LEVEL_INFO, TFLAG_HCI, (" TargetId: %d", _VerboseConfig->TargetId));
	DoTrace(LEVEL_INFO, TFLAG_HCI, (" BuildBase: %d", _VerboseConfig->BuildBase));
	DoTrace(LEVEL_INFO, TFLAG_HCI, (" BuildNum: %d", _VerboseConfig->BuildNum));

Done:
	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-BcmHciGetVerboseConfig %!STATUS!", Status));
	return Status;
}

NTSTATUS
BcmHciGetLocalName(
	_In_     WDFIOTARGET     _IoTargetSerial,
	_In_opt_ WDFREQUEST      _ReusableRequest,
	_Inout_  PUNICODE_STRING _Name
)
/*++

Routine Description:

	This function gets the local name from the Bluetooth device.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_Name - returned name (up to the value of the MaximumLength member)

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	UCHAR ReadBuffer[MAX_HCI_EVENT_SIZE] = { 0 };
	ULONG_PTR BytesRead = 0;
	ANSI_STRING NameAnsiString;

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+BcmHciGetLocalName"));

	UCHAR Command[] = { 0x14, 0x0C, 0x00 };

	Status = SendHciCommandSync(_IoTargetSerial,
		_ReusableRequest,
		Command,
		sizeof(Command),
		NULL
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = ReadHciEventSync(_IoTargetSerial,
		_ReusableRequest,
		ReadBuffer,
		sizeof(ReadBuffer),
		&BytesRead
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = HciVerifyEvent(Command, sizeof(Command), ReadBuffer, (ULONG)BytesRead);

	if (!NT_SUCCESS(Status))
		goto Done;

	RtlInitAnsiString(&NameAnsiString, (PCSZ)ReadBuffer + 6);

	DoTrace(LEVEL_INFO, TFLAG_HCI, (" Complete local name: %s", NameAnsiString.Buffer));

	// Do not return more characters than requested
	if (_Name->MaximumLength / sizeof(WCHAR) < NameAnsiString.MaximumLength)
	{
		NameAnsiString.MaximumLength = _Name->MaximumLength / sizeof(WCHAR);
		NameAnsiString.Length = NameAnsiString.MaximumLength - 1;
	}

	Status = RtlAnsiStringToUnicodeString(_Name, &NameAnsiString, FALSE);

	if (NT_SUCCESS(Status))
		DoTrace(LEVEL_INFO, TFLAG_HCI, (" Local name (unicode request): %wZ", _Name));
	else
	{
		DoTrace(LEVEL_ERROR, TFLAG_HCI, (" RtlAnsiStringToUnicodeString failed %!STATUS!", Status));
		goto Done;
	}
Done:
	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-BcmHciGetLocalName %!STATUS!", Status));
	return Status;
}

NTSTATUS
BcmHciEnterFwDownloadMode(
	_In_     WDFIOTARGET _IoTargetSerial,
	_In_opt_ WDFREQUEST  _ReusableRequest
)
/*++

Routine Description:

	This function is called by BcmHciDownloadFirmware to put the Bluetooth device in
	Minidriver download mode through a vendor-specific HCI command.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	UCHAR ReadBuffer[MAX_HCI_EVENT_SIZE] = { 0 };
	ULONG_PTR BytesRead = 0;

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+BcmHciEnterFwDownloadMode"));

	UCHAR Command[] = { 0x2e, 0xfc, 0x00 };

	Status = SendHciCommandSync(_IoTargetSerial,
		_ReusableRequest,
		Command,
		sizeof(Command),
		NULL
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = ReadHciEventSync(_IoTargetSerial,
		_ReusableRequest,
		ReadBuffer,
		sizeof(ReadBuffer),
		&BytesRead
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = HciVerifyEvent(Command, sizeof(Command), ReadBuffer, (ULONG)BytesRead);

	if (!NT_SUCCESS(Status))
		goto Done;

	SleepMicroseconds(BCM_ENTER_FW_DOWNLOAD_MODE_DELAY_MICROS);
Done:
	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-BcmHciEnterFwDownloadMode %!STATUS!", Status));
	return Status;
}

NTSTATUS
BcmHciDownloadFirmware(
	_In_     WDFIOTARGET     _IoTargetSerial,
	_In_opt_ WDFREQUEST      _ReusableRequest,
	_In_     PUNICODE_STRING _FilePath
)
/*++

Routine Description:

	This function downloads a HCD firmware file on the Bluetooth device.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_FilePath - the path to the firmware file

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES Attributes;
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInfo;
	ULONG_PTR HciBytesRead = 0;
	LARGE_INTEGER ByteOffset;
	UCHAR ReadBuffer[MAX_HCI_EVENT_SIZE] = { 0 };
	UCHAR FileBuffer[1024];

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+BcmHciDownloadFirmware (_FilePath: %wZ)", _FilePath));

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		Status = STATUS_INVALID_DEVICE_STATE;
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" IRQL is higher than PASSIVE_LEVEL!"));
		goto Done;
	}

	InitializeObjectAttributes(&Attributes, _FilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	Status = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&Attributes, &IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (!NT_SUCCESS(Status))
	{
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" ZwCreateFile failed %!STATUS!", Status));
		goto Done;
	}

	Status = ZwQueryInformationFile(FileHandle,
		&IoStatusBlock,
		&FileInfo,
		sizeof(FileInfo),
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" ZwQueryInformationFile failed %!STATUS!", Status));
		goto Done;
	}

	Status = BcmHciEnterFwDownloadMode(_IoTargetSerial, _ReusableRequest);

	if (!NT_SUCCESS(Status))
		goto Done;

	ByteOffset.QuadPart = 0;

	while (ByteOffset.QuadPart < FileInfo.EndOfFile.QuadPart)
	{
		//
		// Read opcode (16-bit) + parameters length
		//
		Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
			FileBuffer, 3, &ByteOffset, NULL);

		if (!NT_SUCCESS(Status))
			goto Done;

		ByteOffset.QuadPart += 3;

		ULONG DataLength = FileBuffer[2];

		// 
		// Read the patch data
		//
		Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
			FileBuffer + 3, DataLength, &ByteOffset, NULL);

		if (!NT_SUCCESS(Status))
			goto Done;

		ByteOffset.QuadPart += DataLength;

		Status = SendHciCommandSync(_IoTargetSerial,
			_ReusableRequest,
			FileBuffer,
			DataLength + 3,
			NULL);

		if (!NT_SUCCESS(Status))
			goto Done;

		Status = ReadHciEventSync(_IoTargetSerial,
			_ReusableRequest,
			ReadBuffer,
			sizeof(ReadBuffer),
			&HciBytesRead);

		if (!NT_SUCCESS(Status))
			goto Done;

		Status = HciVerifyEvent(FileBuffer, DataLength + 3, ReadBuffer, (ULONG)HciBytesRead);

		if (!NT_SUCCESS(Status))
			goto Done;
	}

	SleepMicroseconds(BCM_FW_DOWNLOAD_COMPLETE_DELAY_MICROS);

Done:
	if (FileHandle != NULL)
		ZwClose(FileHandle);

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-BcmHciDownloadFirmware %!STATUS!", Status));
	return Status;
}

NTSTATUS
BcmHciSetBaudRate(
	_In_     WDFIOTARGET _IoTargetSerial,
	_In_opt_ WDFREQUEST  _ReusableRequest,
	_In_     ULONG       _BaudRate
)
/*++

Routine Description:

	This function sets the baud rate of the Bluetooth device through a vendor-specific HCI command.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_BaudRate - the desired baud rate

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	UCHAR ReadBuffer[MAX_HCI_EVENT_SIZE] = { 0 };
	ULONG_PTR BytesRead = 0;

	DoTrace(LEVEL_INFO, TFLAG_HCI, ("+BcmHciSetBaudRate: %d", _BaudRate));

	UCHAR Command[] = { 0x18, 0xfc, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	Command[5] = (UCHAR)(_BaudRate);
	Command[6] = (UCHAR)(_BaudRate >> 8);
	Command[7] = (UCHAR)(_BaudRate >> 16);
	Command[8] = (UCHAR)(_BaudRate >> 24);

	Status = SendHciCommandSync(_IoTargetSerial,
		_ReusableRequest,
		Command,
		sizeof(Command),
		NULL
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = ReadHciEventSync(_IoTargetSerial,
		_ReusableRequest,
		ReadBuffer,
		sizeof(ReadBuffer),
		&BytesRead
	);

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = HciVerifyEvent(Command, sizeof(Command), ReadBuffer, (ULONG)BytesRead);

	if (!NT_SUCCESS(Status))
		goto Done;
Done:
	DoTrace(LEVEL_INFO, TFLAG_HCI, ("-BcmHciSetBaudRate %!STATUS!", Status));
	return Status;
}

NTSTATUS
SetBaudRate(
	_In_     WDFIOTARGET _IoTargetSerial,
	_In_opt_ WDFREQUEST  _ReusableRequest,
	_In_     ULONG       _BaudRate
)
/*++

Routine Description:

	This function sets the baud rate of both the Bluetooth device
	and the host UART controller.

Arguments:

	_IoTargetSerial - the serial I/O target
	_ReusableRequest - (optional) a reusable WDF request to issue serial control

	_BaudRate - the desired baud rate

Return Value:

	NTSTATUS

--*/
{
	NTSTATUS Status = STATUS_SUCCESS;
	SERIAL_BAUD_RATE SerialBaudRate;
	SERIAL_COMMPROP SerialProperties = { 0 };
	ULONG_PTR BytesWritten = 0;

	DoTrace(LEVEL_INFO, TFLAG_UART, ("+SetBaudRate (host + target UART): %d", _BaudRate));

	Status = SendIoctlToIoTargetSync(_IoTargetSerial,
		_ReusableRequest,
		IOCTL_SERIAL_GET_PROPERTIES,
		NULL,
		0,
		&SerialProperties,
		sizeof(SERIAL_COMMPROP),
		&BytesWritten);

	if (!NT_SUCCESS(Status))
		goto Done;

	if (BytesWritten == 0)
	{
		Status = STATUS_UNSUCCESSFUL;
		goto Done;
	}

	if (_BaudRate > SerialProperties.MaxBaud)
	{
		_BaudRate = SerialProperties.MaxBaud;
		DoTrace(LEVEL_WARNING, TFLAG_UART, (" Baud rate capped at %d (maximum supported by host UART)", _BaudRate));
	}

	if (!NT_SUCCESS(Status))
		goto Done;

	Status = BcmHciSetBaudRate(_IoTargetSerial,
		_ReusableRequest,
		_BaudRate);

	if (!NT_SUCCESS(Status))
		goto Done;

	SerialBaudRate.BaudRate = _BaudRate;

	Status = SendIoctlToIoTargetSync(_IoTargetSerial,
		_ReusableRequest,
		IOCTL_SERIAL_SET_BAUD_RATE,
		&SerialBaudRate,
		sizeof(SERIAL_BAUD_RATE),
		NULL,
		0,
		NULL);

	if (!NT_SUCCESS(Status))
		goto Done;

Done:
	DoTrace(LEVEL_INFO, TFLAG_UART, ("-SetBaudRate %!STATUS!", Status));
	return Status;
}

BOOLEAN
CheckRegQueryOperation(
	_In_ NTSTATUS         _Status,
	_In_ PCUNICODE_STRING _ValueName
)
/*++

Routine Description:

	This function checks if the registry query operation was successfully completed,
	and prints a WPP trace in case of failure.

Arguments:

	_Status - NTSTATUS code returned by a call to WdfRegistryQuery[type]
	_ValueName - registry key name

Return Value:

	BOOLEAN

--*/
{
	if (NT_SUCCESS(_Status))
		return TRUE;
	else
	{
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRegistryQuery... (_ValueName: %wZ) failed %!STATUS!", _ValueName, _Status));
		return FALSE;
	}
}

VOID
DeviceQueryDeviceParameters(
	_In_ WDFDRIVER  _Driver
)
/*++

Routine Description:

	Query driver's registry location for device specific parameters.

Arguments:

	_Driver - WDF Driver object

Return Value:

	None

--*/
{
	WDFKEY Key;
	NTSTATUS Status;
	UNICODE_STRING ValueName;
	ULONG Value = 0;
	WDF_OBJECT_ATTRIBUTES Attributes;
	PDEVICE_CONFIG_PARAMETERS ConfigParams = NULL;

	PAGED_CODE();

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+DeviceQueryDeviceParameters"));

	WDF_OBJECT_ATTRIBUTES_INIT(&Attributes);
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attributes, DEVICE_CONFIG_PARAMETERS);

	Status = WdfObjectAllocateContext(_Driver, &Attributes, &ConfigParams);

	if (!NT_SUCCESS(Status))
	{
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfObjectAllocateContext failed %!STATUS!", Status));
		goto Done;
	}

	//
	// Load the default values first
	//
	ConfigParams->BaudRate = DEFAULT_BAUD_RATE;
	ConfigParams->SkipFwDownload = DEFAULT_SKIP_FW_DOWNLOAD;
	RtlInitUnicodeString(&ConfigParams->FwDirectory, DEFAULT_FW_DIRECTORY);

	Status = WdfDriverOpenParametersRegistryKey(_Driver,
		GENERIC_READ,
		WDF_NO_OBJECT_ATTRIBUTES,
		&Key);

	if (NT_SUCCESS(Status))
	{
		//
		// Read BaudRate
		//
		RtlInitUnicodeString(&ValueName, STR_REG_BAUDRATE);
		Status = WdfRegistryQueryULong(Key, &ValueName, &Value);
		if (CheckRegQueryOperation(Status, &ValueName))
			ConfigParams->BaudRate = Value;

		//
		// Read SkipFwDownload
		//
		RtlInitUnicodeString(&ValueName, STR_REG_SKIP_FW_DOWNLOAD);
		Status = WdfRegistryQueryULong(Key, &ValueName, &Value);
		if (CheckRegQueryOperation(Status, &ValueName))
			ConfigParams->SkipFwDownload = Value;

		//
		// Read FwDirectory
		//
		RtlInitUnicodeString(&ValueName, STR_REG_FW_DIRECTORY);
		Status = WdfRegistryQueryUnicodeString(Key, &ValueName, NULL, &ConfigParams->FwDirectory);
		if (CheckRegQueryOperation(Status, &ValueName))
			ConfigParams->SkipFwDownload = Value;

		WdfRegistryClose(Key);
	}
	else
	{
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfDriverOpenParametersRegistryKey failed %!STATUS!", Status));
		goto Done;
	}

Done:
	DoTrace(LEVEL_INFO, TFLAG_IO, ("-DeviceQueryDeviceParameters"));
}

NTSTATUS
DeviceEnableWakeControl(
	_In_  WDFDEVICE          _Device,
	_In_  SYSTEM_POWER_STATE _PowerState
)
/*++

Routine Description:

	Vendor: This is a device specific function, and it arms the wake mechanism
	for this driver to receive the wake signal.  This could be using an
	HOST_WAKE GPIO interrupt, or inband CTS/RTS mechanism.

Arguments:

	_Device - WDF Device object
	_PowerState - Context used for reading data from target UART device

Return Value:

	NTSTATUS

--*/
{
	UNREFERENCED_PARAMETER(_Device);
	UNREFERENCED_PARAMETER(_PowerState);

	return STATUS_SUCCESS;
}

VOID
DeviceDisableWakeControl(
	WDFDEVICE _Device
)
/*++

Routine Description:

	Vendor: This is a device specific function, and it disarms the wake mechanism
	for this driver to receive the wake signal.

Arguments:

	_Device - WDF Device object

Return Value:

	VOID

--*/
{
	UNREFERENCED_PARAMETER(_Device);

	return;
}

BOOLEAN
DeviceInitialize(
	_In_  PFDO_EXTENSION _FdoExtension,
	_In_  WDFIOTARGET    _IoTargetSerial,
	_In_  WDFREQUEST     _RequestSync,
	_In_  BOOLEAN        _IsUartReset
)
/*++

Routine Description:

	This function performs device specific operations to
	bring it into a fully functional state.

Arguments:

	_FdoExtension - Function device object extension

	_IoTargetSerial - IO Target to issue request to serial port

	_RequestSync - A reusable WDF Request to issue serial control

	-IsUartReset - UART reset is required

Return Value:

	TRUE if initialization is completed and successful; FALSE otherwise.

--*/
{
	UNREFERENCED_PARAMETER(_FdoExtension);
	UNREFERENCED_PARAMETER(_IsUartReset);

	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING NamePrefix, LocalName, FirmwarePath;
	WCHAR LocalNameBuffer[BCM_INITIAL_LOCAL_NAME_MAX_LENGTH];
	BCM_HCI_VERBOSE_CONFIG BcmVerboseConfig;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("+DeviceInitialize"));

	PDEVICE_CONFIG_PARAMETERS ConfigParameters = GetDeviceConfigParameters(WdfGetDriver());

	if (ConfigParameters == NULL)
	{
		DoTrace(LEVEL_ERROR, TFLAG_IO, (" ConfigParameters context is uninitialized!"));
		return FALSE;
	}

	RtlUnicodeStringInit(&NamePrefix, BCM_INITIAL_LOCAL_NAME_PREFIX);
	RtlInitEmptyUnicodeString(&LocalName, LocalNameBuffer, sizeof(LocalNameBuffer));
	RtlUnicodeStringInit(&FirmwarePath, NULL);

	Status = BcmHciReset(_IoTargetSerial, _RequestSync);

	if (!NT_SUCCESS(Status))
		return FALSE;

	if (!ConfigParameters->SkipFwDownload)
	{
		Status = BcmHciGetVerboseConfig(_IoTargetSerial,
			_RequestSync,
			&BcmVerboseConfig);

		if (!NT_SUCCESS(Status))
			return FALSE;

		//
		// If BuildNum is 0 then the patch RAM is empty and we have to download the firmware.
		// Once downloaded, we can't update it.
		//
		if (BcmVerboseConfig.BuildNum == 0)
		{
			Status = BcmHciGetLocalName(_IoTargetSerial,
				_RequestSync,
				&LocalName);

			if (!NT_SUCCESS(Status))
				return FALSE;

			if (!RtlPrefixUnicodeString(&NamePrefix, &LocalName, FALSE))
			{
				// This shouldn't happen unless the user messes with the SkipFwDownload reg key.
				DoTrace(LEVEL_ERROR, TFLAG_IO, (" Initial local name was changed. Can't find the firmware!"));
				return FALSE;
			}

			Status = BuildFirmwarePath(&FirmwarePath,
				&ConfigParameters->FwDirectory,
				&LocalName);

			if (!NT_SUCCESS(Status))
			{
				DoTrace(LEVEL_ERROR, TFLAG_IO, (" BuildFirmwarePath failed %!STATUS!", Status));
				return FALSE;
			}

			Status = BcmHciDownloadFirmware(_IoTargetSerial,
				_RequestSync,
				&FirmwarePath);

			if (FirmwarePath.Buffer != NULL)
				ExFreePool(FirmwarePath.Buffer);

			if (!NT_SUCCESS(Status))
				return FALSE;
		}
		else
			DoTrace(LEVEL_INFO, TFLAG_IO, (" Firmware is already installed!"));
	}
	else
		DoTrace(LEVEL_WARNING, TFLAG_IO, (" Firmware download skipped!"));

	Status = SetBaudRate(_IoTargetSerial,
		_RequestSync,
		ConfigParameters->BaudRate);

	if (!NT_SUCCESS(Status))
		return FALSE;

	DoTrace(LEVEL_INFO, TFLAG_IO, ("-DeviceInitialize"));

	return TRUE;
}

NTSTATUS
DeviceEnable(
	_In_ WDFDEVICE _Device,
	_In_ BOOLEAN   _IsEnabled
)

/*++

Routine Description:

	This function enable/wake serial bus device.

Arguments:

	_Device - Supplies a handle to the framework device object.

	_IsEnabled - Boolean to enable or disable the BT device.


Return Value:

	NTSTATUS code.

--*/

{
	UNREFERENCED_PARAMETER(_Device);
	UNREFERENCED_PARAMETER(_IsEnabled);

	return STATUS_SUCCESS;
}


NTSTATUS
DevicePowerOn(
	_In_  WDFDEVICE _Device
)
/*++

Routine Description:

	This routine powers on the serial bus device

Arguments:

	_Device - Supplies a handle to the framework device object.

Return Value:

	NT status code.

--*/
{
	UNREFERENCED_PARAMETER(_Device);

	return STATUS_SUCCESS;
}

NTSTATUS
DevicePowerOff(
	_In_  WDFDEVICE _Device
)
/*++

Routine Description:

	This routine powers off the serial bus device

Arguments:

	_Device - Supplies a handle to the framework device object.

Return Value:

	NT status code.

--*/
{
	UNREFERENCED_PARAMETER(_Device);

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DeviceDoPLDR(
	WDFDEVICE _Fdo
)
/*++

Routine Description:

	This vendor-specific routine takes appropriate actions necessary to fully reset the device.

Arguments:

	_Fdo - Framework device object representing the FDO.

Return Value:

	VOID.

--*/
{
	UNREFERENCED_PARAMETER(_Fdo);
}
