#ifndef __DEBUGDEF_H__
#define __DEBUGDEF_H__

//
// Device control Guid
// {356c5a06-4c26-4b43-a8bb-d209ecd93cde}
//
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(cywbtserialbus,(356c5a06,4c26,4b43,a8bb,d209ecd93cde),  \
        WPP_DEFINE_BIT(TFLAG_PNP)           \
        WPP_DEFINE_BIT(TFLAG_POWER)         \
        WPP_DEFINE_BIT(TFLAG_UART)          \
        WPP_DEFINE_BIT(TFLAG_IOCTL)         \
        WPP_DEFINE_BIT(TFLAG_IO)            \
        WPP_DEFINE_BIT(TFLAG_DATA)          \
        WPP_DEFINE_BIT(TFLAG_HCI))          

//
// Define shorter versions of the ETW trace levels
//
#define LEVEL_CRITICAL  TRACE_LEVEL_CRITICAL
#define LEVEL_ERROR     TRACE_LEVEL_ERROR
#define LEVEL_WARNING   TRACE_LEVEL_WARNING
#define LEVEL_INFO      TRACE_LEVEL_INFORMATION
#define LEVEL_VERBOSE   TRACE_LEVEL_VERBOSE

#define WPP_LEVEL_FLAG_ENABLED(lvl, component) \
    (WPP_LEVEL_ENABLED(component) && WPP_CONTROL(WPP_BIT_ ## component).Level >=lvl)
    
#define WPP_LEVEL_FLAG_LOGGER(lvl, component) \
    WPP_LEVEL_LOGGER(component)

//
// IFR enable macros
//
#define WPP_RECORDER_LEVEL_FLAG_ARGS(lvl, component) \
    WPP_CONTROL(WPP_BIT_ ## component).AutoLogContext, 0, WPP_BIT_ ## component
#define WPP_RECORDER_LEVEL_FLAG_FILTER(lvl, component) \
    (lvl < TRACE_LEVEL_VERBOSE || WPP_CONTROL(WPP_BIT_ ## component).AutoLogVerboseEnabled)

//
// Use for WPP trace
//
#define WithinRange(min, value, max) (min <= value && value <= max)
#define MinToPrint(val1, val2) (val1 < val2 ? val1 : val2)
#define MAX_EVENT_PARAMS_TO_DISPLAY     8   // maximun number of event parameter to be printed (WPP)
#define MAX_COMMAND_PARAMS_TO_DISPLAY   8   // maximun number of vommand parameter to be printed (WPP)

#endif // __DEBUGDEF_H__
