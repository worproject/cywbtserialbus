/*++

Copyright (c) Microsoft Corporation All Rights Reserved

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

#ifndef __PUBLIC_H
#define __PUBLIC_H

#ifdef DEFINE_GUID

//
// Device interface GUID for Bluetooth Radio On/off.
//
DEFINE_GUID(GUID_DEVINTERFACE_BLUETOOTH_RADIO_ONOFF_VENDOR_SPECIFIC,
        0xa8357a1d, 0xc311, 0x49d6, 0x94, 0x3e, 0x21, 0x81, 0x62, 0x3a, 0x1f, 0xef);
//{a8357a1d-c311-49d6-943e-2181623a1fef}

#endif // #ifdef DEFINE_GUID 


//
// IOCTL definitions to support Radio on/off
//
#define FILE_DEVICE_BUSENUM       FILE_DEVICE_BUS_EXTENDER
#define BUSENUM_IOCTL(id, access) CTL_CODE(FILE_DEVICE_BUSENUM, \
                                           (id),                \
                                           METHOD_BUFFERED,     \
                                           access)

#define IOCTL_BUSENUM_SET_RADIO_ONOFF_VENDOR_SPECFIC        BUSENUM_IOCTL(0x1, FILE_WRITE_DATA)

#endif
