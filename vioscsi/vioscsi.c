/*
 * This file contains vioscsi StorPort miniport driver
 *
 * Copyright (c) 2012-2017 Red Hat, Inc.
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "vioscsi.h"
#include "helper.h"
#include "vioscsidt.h"
#include "trace.h"

#if defined(EVENT_TRACING)
#include "vioscsi.tmh"
#endif


#define MS_SM_HBA_API
#include <hbapiwmi.h>

#include <hbaapi.h>
#include <ntddscsi.h>

#define VioScsiWmi_MofResourceName        L"MofResource"

#include "resources.h"
#include "..\Tools\vendor.ver"

#define VIOSCSI_SETUP_GUID_INDEX               0
#define VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX   1
#define VIOSCSI_MS_PORT_INFORM_GUID_INDEX      2

BOOLEAN IsCrashDumpMode;

sp_DRIVER_INITIALIZE DriverEntry;
HW_INITIALIZE        VioScsiHwInitialize;
HW_BUILDIO           VioScsiBuildIo;
HW_STARTIO           VioScsiStartIo;
HW_FIND_ADAPTER      VioScsiFindAdapter;
HW_RESET_BUS         VioScsiResetBus;
HW_ADAPTER_CONTROL   VioScsiAdapterControl;
HW_UNIT_CONTROL      VioScsiUnitControl;
HW_INTERRUPT         VioScsiInterrupt;
HW_DPC_ROUTINE       VioScsiCompleteDpcRoutine;
HW_PASSIVE_INITIALIZE_ROUTINE         VioScsiPassiveDpcInitializeRoutine;
HW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE VioScsiMSInterrupt;


#ifdef EVENT_TRACING
PVOID TraceContext = NULL;
VOID WppCleanupRoutine(PVOID arg1) {
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " WppCleanupRoutine\n");
    WPP_CLEANUP(NULL, TraceContext);
}
#endif

BOOLEAN
VioScsiHwInitialize(
    IN PVOID DeviceExtension
    );

BOOLEAN
VioScsiHwReinitialize(
    IN PVOID DeviceExtension
    );

BOOLEAN
VioScsiBuildIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

BOOLEAN
VioScsiStartIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

ULONG
VioScsiFindAdapter(
    IN PVOID DeviceExtension,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    IN PBOOLEAN Again
    );

BOOLEAN
VioScsiResetBus(
    IN PVOID DeviceExtension,
    IN ULONG PathId
    );

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(
    IN PVOID DeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    );

SCSI_UNIT_CONTROL_STATUS
VioScsiUnitControl(
    IN PVOID DeviceExtension,
    IN SCSI_UNIT_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    );

UCHAR
VioScsiProcessPnP(
    IN PVOID  DeviceExtension,
    IN PSRB_TYPE Srb
);

BOOLEAN
FORCEINLINE
PreProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN PVOID InlineFuncName
    );

VOID
FORCEINLINE
PostProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN PVOID InlineFuncName
    );

BOOLEAN
FORCEINLINE
DispatchQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageId,
    IN PVOID InlineFuncName
    );

BOOLEAN
VioScsiInterrupt(
    IN PVOID DeviceExtension
    );

VOID
TransportReset(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
ParamChange(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

BOOLEAN
VioScsiMSInterrupt(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageId
    );

VOID
VioScsiWmiInitialize(
    IN PVOID  DeviceExtension
    );

VOID
VioScsiWmiSrb(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    );

VOID
VioScsiIoControl(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    );

BOOLEAN
VioScsiQueryWmiDataBlock(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG OutBufferSize,
    OUT PUCHAR Buffer
    );

UCHAR
VioScsiExecuteWmiMethod(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG MethodId,
    IN ULONG InBufferSize,
    IN ULONG OutBufferSize,
    IN OUT PUCHAR Buffer
    );

UCHAR
VioScsiQueryWmiRegInfo(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    OUT PWCHAR *MofResourceName
    );

VOID
VioScsiReadExtendedData(
    IN PVOID Context,
    OUT PUCHAR Buffer
   );

VOID
VioScsiSaveInquiryData(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    );

VOID
VioScsiPatchInquiryData(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    );

GUID VioScsiWmiExtendedInfoGuid = VioScsiWmi_ExtendedInfo_Guid;
GUID VioScsiWmiAdapterInformationQueryGuid = MS_SM_AdapterInformationQueryGuid;
GUID VioScsiWmiPortInformationMethodsGuid = MS_SM_PortInformationMethodsGuid;

SCSIWMIGUIDREGINFO VioScsiGuidList[] =
{
   { &VioScsiWmiExtendedInfoGuid,            1, 0 },
   { &VioScsiWmiAdapterInformationQueryGuid, 1, 0 },
   { &VioScsiWmiPortInformationMethodsGuid,  1, 0 },
};

#define VioScsiGuidCount (sizeof(VioScsiGuidList) / sizeof(SCSIWMIGUIDREGINFO))

void CopyUnicodeString(void* _pDest, const void* _pSrc, size_t _maxlength)
{
     PUSHORT _pDestTemp = _pDest;
     USHORT  _length = _maxlength - sizeof(USHORT);
     *_pDestTemp++ = _length;
     _length = (USHORT)min(wcslen(_pSrc)*sizeof(WCHAR), _length);
     memcpy(_pDestTemp, _pSrc, _length);
}

void CopyAnsiToUnicodeString(void* _pDest, const void* _pSrc, size_t _maxlength)
{
    PUSHORT _pDestTemp = _pDest;
    PWCHAR  dst;
    PCHAR   src = (PCHAR)_pSrc;
    USHORT  _length = _maxlength - sizeof(USHORT);
    *_pDestTemp++ = _length;
    dst = (PWCHAR)_pDestTemp;
    _length = (USHORT)min(strlen((const char*)_pSrc) * sizeof(WCHAR), _length);
    _length /= sizeof(WCHAR);
    while (_length) {
        *dst++ = *src++;
        --_length;
    };
}

USHORT CopyBufferToAnsiString(void* _pDest, const void* _pSrc, const char delimiter, size_t _maxlength)
{
    PCHAR  dst = (PCHAR)_pDest;
    PCHAR   src = (PCHAR)_pSrc;
    USHORT  _length = _maxlength;

    while (_length && (*src != delimiter)) {
        *dst++ = *src++;
        --_length;
    };
    *dst = '\0';
    return _length;
}

BOOLEAN VioScsiReadRegistryParameter(
    IN PVOID DeviceExtension,
    IN PUCHAR ValueName,
    IN LONG offset
)
{
    BOOLEAN Ret = FALSE;
    ULONG Len = sizeof(ULONG);
    UCHAR* pBuf = NULL;
    PADAPTER_EXTENSION adaptExt;
    #if !defined(RUN_UNCHECKED)
    CHAR valname_as_str[30]; //Let me have 30 characters for the Registry Value
    
    ULONG value_as_ulong, i;
    #endif
    
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    pBuf = StorPortAllocateRegistryBuffer(DeviceExtension, &Len);
    if (pBuf == NULL) {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_WARNING, " StorPortAllocateRegistryBuffer failed to allocate buffer\n");
        #endif
        return FALSE;
    }

    memset(pBuf, 0, sizeof(ULONG));

    //FIXME : THIS DOES NOT WORK. IT WILL NOT READ DEVICE(d) subkeys...
    
    // Note we also only look for MINIPORT_REG_DWORD values.
    Ret = StorPortRegistryRead(DeviceExtension,
                               ValueName,
                               0,
                               MINIPORT_REG_DWORD,
                               pBuf,
                               &Len);

    if ((Ret == FALSE) || (Len == 0)) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_WARNING, " StorPortRegistryRead was unable to find a per HBA value at the Parameters\\Device(d) subkey. Will attempt to find a global value... \n");
        #endif
        Ret = FALSE;
        Len = sizeof(ULONG);
        memset(pBuf, 0, sizeof(ULONG));

        // FIXME : If we fix the per Device(d) above, fix the below description.
        
        /* Note we only do a "Global" read of the Parameters\Device subkey.
        * Change parameter 3 to zero and enjoy per HBA configuration.
        * 
        * Note we also only look for MINIPORT_REG_DWORD values.
        */
        Ret = StorPortRegistryRead(DeviceExtension,
                                ValueName,
                                1,
                                MINIPORT_REG_DWORD,
                                pBuf,
                                &Len);
    }

    #if !defined(RUN_UNCHECKED)
    /* Give me the first 30 characters of any Registry Value.
     * Value name limit is 16,383 characters, so this is important.
     * NULL-terminated string wraps things up. Used in TRACING.
     */
    CopyBufferToAnsiString(&valname_as_str, ValueName, '\0', 30);

    /* Give me the Registry Value as a ULONG from the pointer.
     * Used in TRACING.
     */
    memcpy(&value_as_ulong, pBuf, sizeof(ULONG));
    #endif
        
    if ((Ret == FALSE) || (Len == 0)) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPortRegistryRead of %s returned NOT FOUND or EMPTY, Len = %d, Possible Len Hint = 0x%x (%lu) \n", valname_as_str, Len, value_as_ulong, value_as_ulong);
        #endif
        StorPortFreeRegistryBuffer(DeviceExtension, pBuf);
        return FALSE;
    } else {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPortRegistryRead of %s returned SUCCESS, Len = %d, Value = 0x%x (%lu) \n", valname_as_str, Len, value_as_ulong, value_as_ulong);
        #endif
        
        StorPortCopyMemory((PVOID)((UINT_PTR)adaptExt + offset),
           (PVOID)pBuf,
           sizeof(ULONG));

        StorPortFreeRegistryBuffer(DeviceExtension, pBuf );

        return TRUE;
    }
}

ULONG
DriverEntry(
    IN PVOID  DriverObject,
    IN PVOID  RegistryPath
    )
{

    HW_INITIALIZATION_DATA hwInitData;
    ULONG                  initResult;

#ifdef EVENT_TRACING
    STORAGE_TRACE_INIT_INFO initInfo;
#endif

    InitializeDebugPrints((PDRIVER_OBJECT)DriverObject, (PUNICODE_STRING)RegistryPath);

    IsCrashDumpMode = FALSE;
    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_FATAL, " Vioscsi driver started...built on %s %s\n", __DATE__, __TIME__);
    #endif
    if (RegistryPath == NULL) {
        IsCrashDumpMode = TRUE;
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Crash dump mode\n");
        #endif
    }

    RtlZeroMemory(&hwInitData, sizeof(HW_INITIALIZATION_DATA));

    hwInitData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);

    hwInitData.HwFindAdapter            = VioScsiFindAdapter;
    hwInitData.HwInitialize             = VioScsiHwInitialize;
    hwInitData.HwStartIo                = VioScsiStartIo;
    hwInitData.HwInterrupt              = VioScsiInterrupt;
    hwInitData.HwResetBus               = VioScsiResetBus;
    hwInitData.HwAdapterControl         = VioScsiAdapterControl;
    hwInitData.HwUnitControl            = VioScsiUnitControl;
    hwInitData.HwBuildIo                = VioScsiBuildIo;

    hwInitData.NeedPhysicalAddresses    = TRUE;
    hwInitData.TaggedQueuing            = TRUE;
    hwInitData.AutoRequestSense         = TRUE;
    hwInitData.MultipleRequestPerLu     = TRUE;

    hwInitData.DeviceExtensionSize      = sizeof(ADAPTER_EXTENSION);
    hwInitData.SrbExtensionSize         = sizeof(SRB_EXTENSION);

    hwInitData.AdapterInterfaceType     = PCIBus;

    /* Virtio doesn't specify the number of BARs used by the device; it may
     * be one, it may be more. PCI_TYPE0_ADDRESSES, the theoretical maximum
     * on PCI, is a safe upper bound.
     */
    hwInitData.NumberOfAccessRanges     = PCI_TYPE0_ADDRESSES;
    hwInitData.MapBuffers               = STOR_MAP_NON_READ_WRITE_BUFFERS;

    hwInitData.SrbTypeFlags             = SRB_TYPE_FLAG_STORAGE_REQUEST_BLOCK;

    initResult = StorPortInitialize(DriverObject,
                                    RegistryPath,
                                    &hwInitData,
                                    NULL);

#ifdef EVENT_TRACING
    TraceContext = NULL;

    memset(&initInfo, 0, sizeof(STORAGE_TRACE_INIT_INFO));
    initInfo.Size = sizeof(STORAGE_TRACE_INIT_INFO);
    initInfo.DriverObject = DriverObject;
    initInfo.NumErrorLogRecords = 5;
    initInfo.TraceCleanupRoutine = WppCleanupRoutine;
    initInfo.TraceContext = NULL;

    WPP_INIT_TRACING(DriverObject, RegistryPath, &initInfo);

    if (initInfo.TraceContext != NULL) {
        TraceContext = initInfo.TraceContext;
    }
#endif

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_NONE, " Vioscsi driver starting...");
    RhelDbgPrint(TRACE_LEVEL_NONE, " Built on %s at %s \n", __DATE__, __TIME__);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Crash dump mode : %s \n", (IsCrashDumpMode) ? "ACTIVATED" : "NOT ACTIVATED");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Initialize funciton returned : 0x%x (%lu) \n", initResult, initResult);
    #endif
    #if !defined(RUN_UNCHECKED)    
    switch (NTDDI_VERSION) {
        case NTDDI_WIN10:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_THRESHOLD | Windows 10.0.10240 | 1507 | Threshold 1 \n");
            break;
        case NTDDI_WIN10_TH2:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_TH2 | Windows 10.0.10586 | 1511 | Threshold 2 \n");
            break;
        case NTDDI_WIN10_RS1:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_RS1 | Windows 10.0.14393 | 1607 | Redstone 1 \n");
            break;
        case NTDDI_WIN10_RS2:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_RS2 | Windows 10.0.15063 | 1703 | Redstone 2 \n");
            break;
        case NTDDI_WIN10_RS3:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_RS3 | Windows 10.0.16299 | 1709 | Redstone 3 \n");
            break;
        case NTDDI_WIN10_RS4:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_RS4 | Windows 10.0.17134 | 1803 | Redstone 4 \n");
            break;
        case NTDDI_WIN10_RS5:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_RS5 | Windows 10.0.17763 | 1809 | Redstone 5 \n");
            break;
        case NTDDI_WIN10_19H1:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_19H1 | Windows 10.0.18362 | 1903 | 19H1 Titanium \n");
            break;
        case NTDDI_WIN10_VB:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_VB | Windows 10.0.19041 | 2004 | Vibranium \n");
            break;
        case NTDDI_WIN10_MN:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_MN | Windows 10.0.19042 | 20H2 | Manganese \n");
            break;
        case NTDDI_WIN10_FE:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_FE | Windows 10.0.19043 | 21H1 | Ferrum \n");
            break;
        case NTDDI_WIN10_CO:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_CO | Windows 10.0.19044-22000 | 21H2 | Cobalt \n");
            break;
        case NTDDI_WIN10_NI:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_NI | Windows 10.0.22449-22631 | 22H2-22H3 | Nickel \n");
            break;
        case NTDDI_WIN10_CU:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN10_CU | Windows 10.0.25057-25236 | 22H2 | Copper \n");
            break;
        case NTDDI_WIN11_ZN:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN11_ZN | Windows 10.0.25246-25398 | Zinc \n");
            break;
        case NTDDI_WIN11_GA:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN11_GA | Windows 10.0.25905-25941 | Gallium \n");
            break;
        case NTDDI_WIN11_GE:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : ABRACADABRA_WIN11_GE | Windows 10.0.25947-26100 | 24H2 | Germanium \n");
            break;
        default:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " NTDDI_VERSION : 0x%x \n", (NTDDI_VERSION));
            break;
    }
    #endif
    return initResult;
}

ULONG
VioScsiFindAdapter(
    IN PVOID DeviceExtension,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    IN PBOOLEAN Again
    )
{

    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION adaptExt;
    PVOID              uncachedExtensionVa;
    USHORT             queueLength = 0;
    ULONG              Size;
    ULONG              HeapSize;
    ULONG              extensionSize;
    ULONG              index;
    ULONG              num_cpus;
    ULONG              max_cpus;
    ULONG              max_queues;
    ULONG              nopb_candidate[3] = { 0 };
    ULONG              max_segments_b4_alignment;

    UNREFERENCED_PARAMETER( HwContext );
    UNREFERENCED_PARAMETER( BusInformation );
    UNREFERENCED_PARAMETER( ArgumentString );
    UNREFERENCED_PARAMETER( Again );

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    RtlZeroMemory(adaptExt, sizeof(ADAPTER_EXTENSION));

    adaptExt->dump_mode  = IsCrashDumpMode;
    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Crash dump mode : %s \n", (adaptExt->dump_mode == IsCrashDumpMode) ? "ACTIVATED" : "NOT ACTIVATED");
    #endif
    adaptExt->hba_id     = HBA_ID;

    /* NOTE: When unset we get -5k IOPS +30us latency (best case)...!
     */
    ConfigInfo->Master                       = TRUE; // +7k IOPS -50us latency
    ConfigInfo->ScatterGather                = TRUE; // +12k IOPS -75us latency

    /* Allow user to force use of Dma32BitAddresses via reg key
    * [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters\Device]
    * "UseDma32BitAddresses"={any dword value here - the value is ignored}
    * 
    * WARNING: Manually setting this increases latency and reduces IOPS
    * 
    * NOTE: StorPort normally sets this to TRUE anyway.
    *       So let StorPort do it for maximum performance.
    *       Only provided in the event StorPort does not enable the feature and it is required.
    */
    if (VioScsiReadRegistryParameter(DeviceExtension, REGISTRY_USE_DMA32BITADDRESSES, FIELD_OFFSET(ADAPTER_EXTENSION, use_Dma32BitAddresses))) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " REGISTRY_USE_DMA32BITADDRESSES was FOUND in the registry. We will set ConfigInfo->Dma32BitAddresses to TRUE. \n");
        #endif
        ConfigInfo->Dma32BitAddresses = TRUE; // -15k IOPS +100us latency (worst case)
    } else {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " REGISTRY_USE_DMA32BITADDRESSES was NOT FOUND in the registry. We will let StorPort manage the Dma32BitAddresses setting. \n");
        #endif
    }

    /*
     * WARNING: Do not set this.
     *          All of these options increase latency and reduce IOPS:
     * 
    ConfigInfo->DmaWidth                     = 0; //<-- This should be zero as initialised by StorPort
    ConfigInfo->DmaWidth                     = Width32Bits; //<-- This should be zero as initialised by StorPort
    ConfigInfo->DmaWidth                     = Width64Bits; //<-- This should be zero as initialised by StorPort
    */

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort : ConfigInfo->Master : %s \n", (ConfigInfo->Master) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort : ConfigInfo->ScatterGather : %s \n", (ConfigInfo->ScatterGather) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort : ConfigInfo->Dma32BitAddresses : %s \n", (ConfigInfo->Dma32BitAddresses) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort : ConfigInfo->DmaWidth : %lu \n", ConfigInfo->DmaWidth);
    #endif

#if defined(NTDDI_WIN10_VB) && (NTDDI_VERSION >= NTDDI_WIN10_VB)
    ConfigInfo->FeatureSupport |= STOR_ADAPTER_DMA_ADDRESS_WIDTH_SPECIFIED;
#endif

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_FEATURE_DEVICE_TELEMETRY flag is : %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_FEATURE_DEVICE_TELEMETRY)) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_FEATURE_STOP_UNIT_DURING_POWER_DOWN flag is: %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_FEATURE_STOP_UNIT_DURING_POWER_DOWN)) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_UNCACHED_EXTENSION_NUMA_NODE_PREFERRED flag is : %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_UNCACHED_EXTENSION_NUMA_NODE_PREFERRED)) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_DMA_V3_PREFERRED flag is: %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_DMA_V3_PREFERRED)) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_FEATURE_ABORT_COMMAND flag is: %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_FEATURE_ABORT_COMMAND)) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_FEATURE_RICH_TEMPERATURE_THRESHOLD  flag is: %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_FEATURE_RICH_TEMPERATURE_THRESHOLD)) ? "ON" : "OFF");
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort Feature Support: STOR_ADAPTER_DMA_ADDRESS_WIDTH_SPECIFIED flag is: %s \n", 
                 (CHECKFLAG(ConfigInfo->FeatureSupport, STOR_ADAPTER_DMA_ADDRESS_WIDTH_SPECIFIED)) ? "ON" : "OFF");
    #endif

#if defined(NTDDI_WIN10_VB) && (NTDDI_VERSION >= NTDDI_WIN10_VB)
    ConfigInfo->DmaAddressWidth              = 64;
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " ConfigInfo->DmaAddressWidth : %s \n", ConfigInfo->DmaAddressWidth);
    #endif
#else
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " ConfigInfo->DmaAddressWidth is NOT supported in this version of the driver. \n");
    #endif
#endif

    ConfigInfo->Dma64BitAddresses            = SCSI_DMA64_MINIPORT_FULL64BIT_SUPPORTED;
    ConfigInfo->WmiDataProvider              = TRUE;
    ConfigInfo->AlignmentMask                = FILE_BYTE_ALIGNMENT;
    ConfigInfo->NumberOfAccessRanges         = PCI_TYPE0_ADDRESSES;
    ConfigInfo->MapBuffers                   = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->SrbType                      = SRB_TYPE_STORAGE_REQUEST_BLOCK;
    ConfigInfo->SynchronizationModel         = StorSynchronizeFullDuplex;
    ConfigInfo->HwMSInterruptRoutine         = VioScsiMSInterrupt;
    ConfigInfo->InterruptSynchronizationMode = InterruptSynchronizePerMessage;

    VioScsiWmiInitialize(DeviceExtension);

    if (!InitHW(DeviceExtension, ConfigInfo)) {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot initialize HardWare\n");
        EXIT_FN();
        #endif
        return SP_RETURN_NOT_FOUND;
    }

    // TODO WIP FOLLOWS
    
    // FIXME Make use of per device, i.e. Parameters\Device(d), e.g. Parameters\Device0, Parameters\Device1, etc.
    // Driver currently only has Parameters\Device-1, which is odd. All HBAs use the same per device key, which is wrong.
    
    /* FIXME
     * This doesn't work (all HBAs report 0) so we cannot rely on it.
     * We are possibly calling it incorrectly...
     * There might be a versioning issue...
     * Have tried in other spots too...
     * SUSPECT no unique IDs per HBA (adaptExt->hba_id)...
     *
     */
    STOR_ADDRESS HwAddress = { 0 };
    HwAddress.Type = STOR_ADDRESS_TYPE_BTL8;
    HwAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
    //HwAddress.Port = (USHORT) adaptExt->slot_number;
    StorPortGetSystemPortNumber(adaptExt, &HwAddress);
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " HBA Port : %u \n", HwAddress.Port);
    #endif

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " slot_number : %lu | system_io_bus_number : %lu | port_idx: : %lu \n", 
                 adaptExt->slot_number, adaptExt->system_io_bus_number, adaptExt->port_idx);
    #endif

    BOOLEAN Ret = FALSE;
    ULONG myScope = 0;
    ULONG myType = MINIPORT_REG_DWORD;
    PUCHAR pBuf = NULL;
    ULONG Len = sizeof(ULONG);
    pBuf = StorPortAllocateRegistryBuffer(DeviceExtension, &Len);
    memset(pBuf, 0, Len);
    memcpy(pBuf, &adaptExt->slot_number, Len);
    #define MY_REG_VALUENAME "HbaPciSlot"
    Ret = StorPortRegistryWrite(DeviceExtension, MY_REG_VALUENAME, myScope, myType, pBuf, Len);
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Writing HBA location information to registry %s \n", (Ret) ? "was SUCCESSFUL." : "FAILED...!!!");
    #endif
    StorPortFreeRegistryBuffer(DeviceExtension, pBuf);
    
    // TODO END WIP
    
    /* Initialize the following variables to temporary values to keep
     * Static Driver Verification happy. These values will be immediately
     * reconfigured within GetScsiConfig below, which will retrieve the runtime
     * values advertised by the underlying device.
     */
    adaptExt->scsi_config.num_queues = 1;
    adaptExt->scsi_config.seg_max    = SCSI_MINIMUM_PHYSICAL_BREAKS;
    adaptExt->indirect               = FALSE;
    adaptExt->max_physical_breaks    = SCSI_MINIMUM_PHYSICAL_BREAKS;
    
    GetScsiConfig(DeviceExtension);
    SetGuestFeatures(DeviceExtension);

    ConfigInfo->NumberOfBuses               = 1;
    ConfigInfo->MaximumNumberOfTargets      = min((UCHAR)adaptExt->scsi_config.max_target, 255/*SCSI_MAXIMUM_TARGETS_PER_BUS*/);
    ConfigInfo->MaximumNumberOfLogicalUnits = min((UCHAR)adaptExt->scsi_config.max_lun, SCSI_MAXIMUM_LUNS_PER_TARGET);
    ConfigInfo->MaximumTransferLength       = SP_UNINITIALIZED_VALUE; // Unlimited
    ConfigInfo->NumberOfPhysicalBreaks      = SP_UNINITIALIZED_VALUE; // Unlimited

    if (!adaptExt->dump_mode) {
        /* Allow user to override max_physical_breaks via reg key
         * [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters\Device]
         * "PhysicalBreaks"={dword value here}
         * 
         * *** This should be VIRTIO_MAX_SG - 1, approximated by the maximum number of memory pages (typ. 4KiB each) - 1 ***
         */
        if (VioScsiReadRegistryParameter(DeviceExtension, REGISTRY_MAX_PH_BREAKS, FIELD_OFFSET(ADAPTER_EXTENSION, max_physical_breaks))) {
            /* We +1 to convert to segments from NOPB */
            adaptExt->max_segments = adaptExt->max_physical_breaks + 1;
            
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " max_physical_breaks candidate was specified in the registry : %lu | max_segments : %lu \n", 
                         adaptExt->max_physical_breaks, adaptExt->max_segments);
            #endif
        } else {
            /* Grab the VirtIO reported maximum SEGMENTS value from the HBA and put it somewhere mutable */
            adaptExt->max_segments = adaptExt->scsi_config.seg_max;
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " max_physical_breaks candidate was NOT specified in the registry. We will attempt to derive the value...\n");
            #endif
        }

        /* Use our maximum SEGMENTS value OR use PHYS_SEGMENTS... */
        nopb_candidate[1] = (adaptExt->indirect) ? (adaptExt->max_segments - 1) : (PHYS_SEGMENTS - 1);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " max_physical_breaks candidate derived from MAX SEGMENTS : %lu \n", nopb_candidate[1]);
        #endif

        /* Grab the VirtIO reported maximum SECTORS value from the HBA to start with */
        nopb_candidate[2] = (adaptExt->scsi_config.max_sectors * SECTOR_SIZE / PAGE_SIZE) - 1;
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " max_physical_breaks candidate derived from MAX SECTORS (QEMU/KVM hint) : %lu \n", nopb_candidate[2]);
        #endif
        
        /* Start with a comparison of equality */
        if (nopb_candidate[1] == nopb_candidate[2]) {
            nopb_candidate[0] = nopb_candidate[1];
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " nopb_candidate[0] : init - the candidates were the same value : %lu \n", nopb_candidate[0]);
            #endif
        } else if (nopb_candidate[2] > 0 && nopb_candidate[2] < (MAX_PHYS_SEGMENTS - 1)) {
            nopb_candidate[0] = nopb_candidate[2];
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " nopb_candidate[0] : init - the QEMU/KVM hint method (scsi_config.max_sectors) was used to select the candidate : %lu \n", nopb_candidate[0]);
            #endif
        } else {
            /* Take the smallest candidate */
            nopb_candidate[0] = min((nopb_candidate[1]), (nopb_candidate[2]));
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " nopb_candidate[0] : init - the smallest candidate was selected : %lu \n", nopb_candidate[0]);
            #endif
        }

        /* Check the value is within SG list bounds */
        nopb_candidate[0] = min(max(SCSI_MINIMUM_PHYSICAL_BREAKS, nopb_candidate[0]), (VIRTIO_MAX_SG - 1));
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " nopb_candidate[0] : within SG list bounds : %lu\n", nopb_candidate[0]);
        #endif

        /* Check the value is within physical bounds */
        nopb_candidate[0] = min(max(SCSI_MINIMUM_PHYSICAL_BREAKS, nopb_candidate[0]), (MAX_PHYS_SEGMENTS - 1));
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " nopb_candidate[0] : within physical bounds : %lu\n", nopb_candidate[0]);
        #endif        

        /* Update max_segments for all cases */
        adaptExt->max_segments = nopb_candidate[0] + 1;
        max_segments_b4_alignment = adaptExt->max_segments;

        /* Do byte alignment (using integer division) if necessary */
        if (max_segments_b4_alignment > (PAGE_SIZE / SECTOR_SIZE)) {
            adaptExt->max_physical_breaks = (((max_segments_b4_alignment / (PAGE_SIZE / SECTOR_SIZE)) * (PAGE_SIZE / SECTOR_SIZE)) - 1);
            if (max_segments_b4_alignment != (adaptExt->max_physical_breaks + 1)) {
                adaptExt->max_segments = adaptExt->max_physical_breaks + 1;
            }
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, 
                         " Sector byte alignment : SECTOR_SIZE = %lu Bytes, PAGE_SIZE = %lu KiB, max_segments : original = %lu, aligned = %lu, max_physical_breaks : original = %lu, aligned = %lu \n", 
                         SECTOR_SIZE, (PAGE_SIZE / 1024), max_segments_b4_alignment, adaptExt->max_segments, nopb_candidate[0], adaptExt->max_physical_breaks);
            #endif
        }
    }
    ConfigInfo->NumberOfPhysicalBreaks = adaptExt->max_physical_breaks;
    /* MaximumTransferLength should be calculated from segments not breaks... */
    ConfigInfo->MaximumTransferLength  = adaptExt->max_segments * PAGE_SIZE;

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " NumberOfSegments : %lu | NumberOfPhysicalBreaks : %lu | MaximumTransferLength : %lu Bytes (%lu KiB) \n", 
                 (ConfigInfo->NumberOfPhysicalBreaks + 1), 
                 ConfigInfo->NumberOfPhysicalBreaks, 
                 ConfigInfo->MaximumTransferLength, 
                 (ConfigInfo->MaximumTransferLength / 1024));
    #endif

    num_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    max_cpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);

    /* Set num_cpus and max_cpus to some sane values, to keep "Static Driver Verification" happy */
    num_cpus = max(1, num_cpus);
    max_cpus = max(1, max_cpus);

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Detected Number Of CPUs : %lu\n", num_cpus);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Maximum  Number Of CPUs : %lu\n", max_cpus);
    #endif

    adaptExt->num_queues = adaptExt->scsi_config.num_queues;
    if (adaptExt->dump_mode || !adaptExt->msix_enabled)
    {
        adaptExt->num_queues = 1;
    }
    else
    {
        adaptExt->num_queues = min(adaptExt->num_queues, (USHORT)num_cpus);
    }

    adaptExt->action_on_reset = VioscsiResetCompleteRequests;
    VioScsiReadRegistryParameter(DeviceExtension, REGISTRY_ACTION_ON_RESET, FIELD_OFFSET(ADAPTER_EXTENSION, action_on_reset));

    adaptExt->resp_time = 0;
    VioScsiReadRegistryParameter(DeviceExtension, REGISTRY_RESP_TIME_LIMIT, FIELD_OFFSET(ADAPTER_EXTENSION, resp_time));

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VirtIO Request Queues : %lu, CPUs : %lu \n", adaptExt->num_queues, num_cpus);
    #endif

    /* Figure out the maximum number of queues we will ever need to set up. Note that this may
     * be higher than adaptExt->num_queues, because the driver may be reinitialized by calling
     * VioScsiFindAdapter again with more CPUs enabled. Unfortunately StorPortGetUncachedExtension
     * only allocates when called for the first time so we need to always use this upper bound.
     */
    if (adaptExt->dump_mode) {
        max_queues = adaptExt->num_queues;
    } else {
        /* Allow user to specify alloc_for_cpu_hotplug via reg key
         * [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters\Device]
         * "AllocForCpuHotplug"={any dword value here - the value is ignored}
         */       
        if (VioScsiReadRegistryParameter(DeviceExtension, REGISTRY_ALLOC_FOR_CPU_HOTPLUG, FIELD_OFFSET(ADAPTER_EXTENSION, alloc_for_cpu_hotplug))) {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " REGISTRY_ALLOC_FOR_CPU_HOTPLUG was FOUND in the registry. We will allocate memory for maxmium possible CPUs. \n");
            #endif
            max_queues = VIRTIO_SCSI_QUEUE_LAST + VIRTIO_SCSI_REQUEST_QUEUE_0;
        } else {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " REGISTRY_ALLOC_FOR_CPU_HOTPLUG was NOT FOUND in the registry. We will allocate memory for currently present CPUs only. \n");
            #endif
            max_queues = min(max_cpus, adaptExt->scsi_config.num_queues) + VIRTIO_SCSI_REQUEST_QUEUE_0;
        }
        if (adaptExt->num_queues > max_queues) {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_WARNING, " !!! WARNING : Multiqueue can only use ONE queue per CPU at most. !!!");
            #endif
            adaptExt->num_queues = max_queues;
        }
    }

    /* This function is our only chance to allocate memory for the driver; allocations are not
     * possible later on. Even worse, the only allocation mechanism guaranteed to work in all
     * cases is StorPortGetUncachedExtension, which gives us one block of physically contiguous
     * pages.
     *
     * Allocations that need to be page-aligned will be satisfied from this one block starting
     * at the first page-aligned offset, up to adaptExt->pageAllocationSize computed below. Other
     * allocations will be cache-line-aligned, of total size adaptExt->poolAllocationSize, also
     * computed below.
     */
    adaptExt->pageAllocationSize = 0;
    adaptExt->poolAllocationSize = 0;
    adaptExt->pageOffset = 0;
    adaptExt->poolOffset = 0;
    Size = 0;
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_FATAL, " START: pageAllocationSize : %lu KiB | Size : %lu KiB | poolAllocationSize : %lu Bytes | HeapSize is not yet defined. \n", 
                 (adaptExt->pageAllocationSize / 1024), (Size /1024), adaptExt->poolAllocationSize);
    #endif
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < max_queues; ++index) {
        virtio_query_queue_allocation(&adaptExt->vdev, index, &queueLength, &Size, &HeapSize);
        if (Size == 0) {
            LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);

            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL, " Virtual queue %lu config failed.\n", index);
            EXIT_FN();
            #endif
            return SP_RETURN_ERROR;
        }
        adaptExt->pageAllocationSize += ROUND_TO_PAGES(Size);
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(HeapSize);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, "  INCR : pageAllocationSize : %lu KiB | Size : %lu KiB | poolAllocationSize : %lu Bytes | HeapSize : %lu Bytes \n", 
                     (adaptExt->pageAllocationSize / 1024), (Size / 1024), adaptExt->poolAllocationSize, HeapSize);
        #endif
    }
    if (!adaptExt->dump_mode) {
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(SRB_EXTENSION));
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(VirtIOSCSIEventNode) * 8);
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(STOR_DPC) * max_queues);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " DUMP : pageAllocationSize : %lu KiB | Size : %lu KiB | poolAllocationSize : %lu Bytes | HeapSize : %lu Bytes \n", 
                     (adaptExt->pageAllocationSize / 1024), (Size / 1024), adaptExt->poolAllocationSize, HeapSize);
        #endif
    }

    if (max_queues > MAX_QUEUES_PER_DEVICE_DEFAULT)
    {
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(
            ((ULONGLONG)max_queues) * virtio_get_queue_descriptor_size());
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " LIMIT: pageAllocationSize : %lu KiB | Size : %lu KiB | poolAllocationSize : %lu Bytes | HeapSize : %lu Bytes \n", 
                     (adaptExt->pageAllocationSize / 1024), (Size / 1024), adaptExt->poolAllocationSize, HeapSize);
        #endif
    }

    if(adaptExt->indirect) {
        adaptExt->queue_depth = queueLength;
    } else {
        adaptExt->queue_depth = queueLength / ConfigInfo->NumberOfPhysicalBreaks;
    }
    ConfigInfo->MaxIOsPerLun = adaptExt->queue_depth * adaptExt->num_queues;
    ConfigInfo->InitialLunQueueDepth = ConfigInfo->MaxIOsPerLun;
    ConfigInfo->MaxNumberOfIO = ConfigInfo->MaxIOsPerLun;

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_FATAL, " FINAL: pageAllocationSize : %lu KiB | Size : %lu KiB | poolAllocationSize : %lu Bytes | HeapSize : %lu Bytes \n", 
                 (adaptExt->pageAllocationSize / 1024), (Size / 1024), adaptExt->poolAllocationSize, HeapSize);
    #endif

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " NumberOfPhysicalBreaks = %lu, MaximumTransferLength = %lu KiB, MaxNumberOfIO = %lu, MaxIOsPerLun = %lu, queueLength = %lu, queue_depth = %lu \n",
                ConfigInfo->NumberOfPhysicalBreaks,
                (ConfigInfo->MaximumTransferLength / 1024),
                ConfigInfo->MaxNumberOfIO,
                ConfigInfo->MaxIOsPerLun,
                queueLength,
                adaptExt->queue_depth);
    #endif

    extensionSize = PAGE_SIZE + adaptExt->pageAllocationSize + adaptExt->poolAllocationSize;
    uncachedExtensionVa = StorPortGetUncachedExtension(DeviceExtension, ConfigInfo, extensionSize);
    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " POINTER : %p, size = %lu Bytes | StorPortGetUncachedExtension [uncachedExtensionVa]\n", uncachedExtensionVa, extensionSize);
    #endif
    if (!uncachedExtensionVa) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " Can't get uncached extension allocation size = %lu\n", extensionSize);
        EXIT_FN();
        #endif
        return SP_RETURN_ERROR;
    }

    /* At this point we have all the memory we're going to need. We lay it out as follows.
     * Note that StorPortGetUncachedExtension tends to return page-aligned memory so the
     * padding1 region will typically be empty and the size of padding2 equal to PAGE_SIZE.
     *
     * uncachedExtensionVa    pageAllocationVa         poolAllocationVa
     * +----------------------+------------------------+--------------------------+----------------------+
     * | \ \ \ \ \ \ \ \ \ \  |<= pageAllocationSize =>|<=  poolAllocationSize  =>| \ \ \ \ \ \ \ \ \ \  |
     * |  \ \  padding1 \ \ \ |                        |                          |  \ \  padding2 \ \ \ |
     * | \ \ \ \ \ \ \ \ \ \  |    page-aligned area   | pool area for cache-line | \ \ \ \ \ \ \ \ \ \  |
     * |  \ \ \ \ \ \ \ \ \ \ |                        | aligned allocations      |  \ \ \ \ \ \ \ \ \ \ |
     * +----------------------+------------------------+--------------------------+----------------------+
     * |<=====================================  extensionSize  =========================================>|
     */

    /* Let's start with the some page alignment */
    adaptExt->pageAllocationVa = (PVOID)(((ULONG_PTR)(uncachedExtensionVa) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1));

    /* If we got a pool allocation, let's get a page allocation */
    if (adaptExt->poolAllocationSize > 0) {
        adaptExt->poolAllocationVa = (PVOID)((ULONG_PTR)adaptExt->pageAllocationVa + adaptExt->pageAllocationSize);
    }
    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " POINTER : %p, size = %lu Bytes | Page-aligned area\n", adaptExt->pageAllocationVa, adaptExt->pageAllocationSize);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " POINTER : %p, size = %lu Bytes | Pool area\n", adaptExt->poolAllocationVa, adaptExt->poolAllocationSize);
    #endif

    /* Let's allocate a memory pool for the CPU affinity masks */
    if ((!adaptExt->dump_mode) && (adaptExt->num_queues > 1) && (adaptExt->pmsg_affinity == NULL)) {

        adaptExt->num_affinity = adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET;

        ULONG Status = StorPortAllocatePool(DeviceExtension,
                        sizeof(GROUP_AFFINITY) * (ULONGLONG)adaptExt->num_affinity,
                        VIOSCSI_POOL_TAG,
                        (PVOID*)&adaptExt->pmsg_affinity);

        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " POINTER : %p, size = %lu Bytes | CPU Affinity [pmsg_affinity] | num_affinity = %lu, StorPortAllocatePool() Status = 0x%x \n", 
                     adaptExt->pmsg_affinity,
                     (sizeof(GROUP_AFFINITY) * (ULONGLONG)adaptExt->num_affinity), 
                     adaptExt->num_affinity, 
                     Status);
        #endif
        #if !defined(RUN_UNCHECKED)
        //FIXME : SDV banned functions
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Higest NUMA Node Number : %lu \n", KeQueryHighestNodeNumber());
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Active CPU KAFFINITY Mask : %I64d \n", KeQueryActiveProcessors());
        #endif
    }

    adaptExt->fw_ver = '0';

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return SP_RETURN_FOUND;
}

BOOLEAN
VioScsiPassiveDpcInitializeRoutine(
    IN PVOID DeviceExtension
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    for (index = 0; index < adaptExt->num_queues; ++index) {
        StorPortInitializeDpc(DeviceExtension,
            &adaptExt->dpc[index],
            VioScsiCompleteDpcRoutine);
    }
    adaptExt->dpc_ok = TRUE;
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return adaptExt->dpc_ok;
}

static BOOLEAN InitializeVirtualQueues(PADAPTER_EXTENSION adaptExt, ULONG numQueues)
{
    NTSTATUS status;

    status = virtio_find_queues(
        &adaptExt->vdev,
        numQueues,
        adaptExt->vq);
    if (!NT_SUCCESS(status)) {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " FAILED with status 0x%x\n", status);
        #endif
        return FALSE;
    }

    return TRUE;
}

PVOID
VioScsiPoolAlloc(
    IN PVOID DeviceExtension,
    IN SIZE_T size
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVOID ptr = (PVOID)((ULONG_PTR)adaptExt->poolAllocationVa + adaptExt->poolOffset);

    if ((adaptExt->poolOffset + size) <= adaptExt->poolAllocationSize) {
        size = ROUND_TO_CACHE_LINES(size);
        adaptExt->poolOffset += (ULONG)size;
        RtlZeroMemory(ptr, size);
        return ptr;
    }
    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_FATAL, " Out of memory %Id \n", size);
    #endif
    return NULL;
}

BOOLEAN
VioScsiHwInitialize(
    IN PVOID DeviceExtension
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG              i;
    ULONG              index;

    PERF_CONFIGURATION_DATA perfData = { 0 };
    ULONG              status = STOR_STATUS_SUCCESS;
    MESSAGE_INTERRUPT_INFORMATION msi_info = { 0 };
    PREQUEST_LIST  element;

    adaptExt->msix_vectors = 0;
    adaptExt->pageOffset = 0;
    adaptExt->poolOffset = 0;

    if ((!adaptExt->dump_mode) && (adaptExt->num_queues > 1) && (adaptExt->perfFlags == 0)) {
        perfData.Version = STOR_PERF_VERSION;
        perfData.Size = sizeof(PERF_CONFIGURATION_DATA);

        status = StorPortInitializePerfOpts(DeviceExtension, TRUE, &perfData);

        if (status == STOR_STATUS_SUCCESS) {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL,
                " PERF: GET PerfOpts : Version = 0x%x, Flags = 0x%x, ConcurrentChannels = %d, FirstRedirectionMessageNumber = %d, LastRedirectionMessageNumber = %d, DeviceNode = %d\n",
                perfData.Version,
                perfData.Flags,
                perfData.ConcurrentChannels,
                perfData.FirstRedirectionMessageNumber,
                perfData.LastRedirectionMessageNumber,
                perfData.DeviceNode);
            #endif
        } else {
            //FIXME...
            //should we not return here with ERROR, or continue with WARNING
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_WARNING, " PERF: StorPortInitializePerfOpts GET failed with status = 0x%x\n", status);
            //EXIT_FN();
            #endif
            //return FALSE;
        }

        if ( (status == STOR_STATUS_SUCCESS) &&
            (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION)) ) {
            adaptExt->perfFlags = STOR_PERF_DPC_REDIRECTION;
            if (CHECKFLAG(perfData.Flags, STOR_PERF_CONCURRENT_CHANNELS)) {
                adaptExt->perfFlags |= STOR_PERF_CONCURRENT_CHANNELS;
                perfData.ConcurrentChannels = adaptExt->num_queues;
            }
            if (CHECKFLAG(perfData.Flags, STOR_PERF_INTERRUPT_MESSAGE_RANGES)) {
                adaptExt->perfFlags |= STOR_PERF_INTERRUPT_MESSAGE_RANGES;
                perfData.FirstRedirectionMessageNumber = VIRTIO_SCSI_REQUEST_QUEUE_0 + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET;
                perfData.LastRedirectionMessageNumber = perfData.FirstRedirectionMessageNumber + perfData.ConcurrentChannels - 1;
            }
        
            ASSERT(perfData.LastRedirectionMessageNumber < adaptExt->num_affinity);
            if ((adaptExt->pmsg_affinity != NULL) && CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY)) {
                RtlZeroMemory((PCHAR)adaptExt->pmsg_affinity, sizeof(GROUP_AFFINITY) * ((ULONGLONG)adaptExt->num_affinity));
                adaptExt->perfFlags |= STOR_PERF_ADV_CONFIG_LOCALITY;
                perfData.MessageTargets = adaptExt->pmsg_affinity;
            }
            if (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION_CURRENT_CPU)) {
                adaptExt->perfFlags |= STOR_PERF_DPC_REDIRECTION_CURRENT_CPU;
            }
            if (CHECKFLAG(perfData.Flags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) {
                adaptExt->perfFlags |= STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO;
            }
            perfData.Flags = adaptExt->perfFlags;
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                " PERF: SET PerfOpts : Version = 0x%x, Flags = 0x%x, ConcurrentChannels = %d, FirstRedirectionMessageNumber = %d, LastRedirectionMessageNumber = %d, DeviceNode = %d\n",
                perfData.Version,
                perfData.Flags,
                perfData.ConcurrentChannels,
                perfData.FirstRedirectionMessageNumber,
                perfData.LastRedirectionMessageNumber,
                perfData.DeviceNode);
            #endif
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_DPC_REDIRECTION flag is : %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION)) ? "ON" : "OFF");
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_CONCURRENT_CHANNELS flag is: %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_CONCURRENT_CHANNELS)) ? "ON" : "OFF");
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_INTERRUPT_MESSAGE_RANGES flag is : %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_INTERRUPT_MESSAGE_RANGES)) ? "ON" : "OFF");
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_ADV_CONFIG_LOCALITY flag is: %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY)) ? "ON" : "OFF");
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO flag is: %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) ? "ON" : "OFF");
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_DPC_REDIRECTION_CURRENT_CPU flag is : %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION_CURRENT_CPU)) ? "ON" : "OFF");
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " PERF: STOR_PERF_NO_SGL flag is : %s \n", 
                            (CHECKFLAG(perfData.Flags, STOR_PERF_NO_SGL)) ? "ON" : "OFF");
            #endif
            
            status = StorPortInitializePerfOpts(DeviceExtension, FALSE, &perfData);

            if (status != STOR_STATUS_SUCCESS) {
                adaptExt->perfFlags = 0;
                #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                RhelDbgPrint(TRACE_LEVEL_ERROR, " PERF: StorPortInitializePerfOpts SET failed with status = 0x%x\n", status);
                #endif
            }
            for (index = 0; index < adaptExt->num_affinity; ++index) {
                GROUP_AFFINITY vector_affinity = adaptExt->pmsg_affinity[index];
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_MSIX_CPU_AFFINITY, 
                        " PERF: MSI-X Vector %lu CPU Affinity : KAFFINITY Mask = %I64d, CPU Group = %lu \n", 
                        index, vector_affinity.Mask, vector_affinity.Group);
                #endif
            }
        }
    }

    while(StorPortGetMSIInfo(DeviceExtension, adaptExt->msix_vectors, &msi_info) == STOR_STATUS_SUCCESS) {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        if (adaptExt->num_queues > 1) {
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, 
                    " MSI-X Vector [MessageId] = %lu, MessageAddress = 0x%I64x, MessageData = %lu, InterruptVector = %lu, InterruptLevel = %lu, InterruptMode = %s, CPU Affinity : Mask = %I64d, Group = %lu \n", 
                    msi_info.MessageId, msi_info.MessageAddress.QuadPart, msi_info.MessageData, 
                    msi_info.InterruptVector, msi_info.InterruptLevel, msi_info.InterruptMode == LevelSensitive ? "LevelSensitive" : "Latched",
                    adaptExt->pmsg_affinity[msi_info.MessageId].Mask, adaptExt->pmsg_affinity[msi_info.MessageId].Group);
        } else {
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, 
                    " MSI-X Vector [MessageId] = %lu, MessageAddress = 0x%I64x, MessageData = %lu, InterruptVector = %lu, InterruptLevel = %lu, InterruptMode = %s \n", 
                    msi_info.MessageId, msi_info.MessageAddress.QuadPart, msi_info.MessageData, 
                    msi_info.InterruptVector, msi_info.InterruptLevel, msi_info.InterruptMode == LevelSensitive ? "LevelSensitive" : "Latched");
        }
        #endif
        ++adaptExt->msix_vectors;
    }

    if (adaptExt->num_queues > 1 &&
        ((adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET) > adaptExt->msix_vectors)) {
        adaptExt->num_queues = (USHORT)adaptExt->msix_vectors;
    }

    if (!adaptExt->dump_mode && adaptExt->msix_vectors > 0) {
        if (adaptExt->msix_vectors >= adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET) {
            /* initialize queues with a MSI vector per queue */
            adaptExt->msix_one_vector = FALSE;
        } else {
            /* if we don't have enough vectors, use one for all queues */
            adaptExt->msix_one_vector = TRUE;
        }
    }
    else {
        /* initialize queues with no MSI interrupts */
        adaptExt->msix_enabled = FALSE;
    }

    if (!InitializeVirtualQueues(adaptExt, adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0)) {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " !!! - Failed to initialize the Virtual Queues - !!!\n");
        EXIT_FN();
        #endif
        return FALSE;
    }

    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VirtIO Request Queues : %d, MSI-X Enabled : %s, MSI-X Use ONE Vector : %s, MSI-X Vectors [msix_vectors] : %d \n", 
            adaptExt->num_queues, 
            (adaptExt->msix_enabled) ? "YES" : "NO", 
            (adaptExt->msix_one_vector) ? "YES" : "NO", 
            adaptExt->msix_vectors);
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " MSI-X Vector %lu | StorPort exclusive control \n", (VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET - 1));
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " MSI-X Vector %lu | VIRTIO Control Queue \n", (VIRTIO_SCSI_CONTROL_QUEUE + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET));
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " MSI-X Vector %lu | VIRTIO Events Queue \n", (VIRTIO_SCSI_EVENTS_QUEUE + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET));
    #endif
    for (index = 0; index < adaptExt->num_queues; ++index) {
        element = &adaptExt->processing_srbs[index];
        InitializeListHead(&element->srb_list);
        element->srb_cnt = 0;
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " MSI-X Vector %lu | VIRTIO Request Queue %lu (index %lu) \n", 
                     (index + VIRTIO_SCSI_REQUEST_QUEUE_0 + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET), (index + 1), index);
        #endif
    }

    if (!adaptExt->dump_mode) {
        /* we don't get another chance to call StorPortEnablePassiveInitialization and initialize
         * DPCs if the adapter is being restarted, so leave our datastructures alone on restart
         */
        if (adaptExt->dpc == NULL) {
            adaptExt->tmf_cmd.SrbExtension = (PSRB_EXTENSION)VioScsiPoolAlloc(DeviceExtension, sizeof(SRB_EXTENSION));
            adaptExt->events = (PVirtIOSCSIEventNode)VioScsiPoolAlloc(DeviceExtension, sizeof(VirtIOSCSIEventNode) * 8);
            adaptExt->dpc = (PSTOR_DPC)VioScsiPoolAlloc(DeviceExtension, sizeof(STOR_DPC) * adaptExt->num_queues);
        }
        
        if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG)) {
            PVirtIOSCSIEventNode events = adaptExt->events;
            for (i = 0; i < 8; i++) {
                if (!KickEvent(DeviceExtension, (PVOID)(&events[i]))) {
                    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                    RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot add event %d\n", i);
                    #endif
                }
            }
        }

        if (!adaptExt->dpc_ok && !StorPortEnablePassiveInitialization(DeviceExtension, VioScsiPassiveDpcInitializeRoutine)) {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL, " StorPortEnablePassiveInitialization FAILED\n");
            EXIT_FN();
            #endif
            return FALSE;
        }
    }

    virtio_device_ready(&adaptExt->vdev);
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return TRUE;
}

BOOLEAN
VioScsiHwReinitialize(
    IN PVOID DeviceExtension
    )
{
    /* The adapter is being restarted and we need to bring it back up without
     * running any passive-level code. Note that VioScsiFindAdapter is *not*
     * called on restart.
     */
    if (!InitVirtIODevice(DeviceExtension)) {
        return FALSE;
    }
    SetGuestFeatures(DeviceExtension);
    return VioScsiHwInitialize(DeviceExtension);
}

BOOLEAN
VioScsiStartIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    if (PreProcessRequest(DeviceExtension, (PSRB_TYPE)Srb, "PreProcessRequest"))
    {
        CompleteRequest(DeviceExtension, (PSRB_TYPE)Srb);
    }
    else
    {
        PADAPTER_EXTENSION adaptExt;
        adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
        
        /* MUST use DpcLock here so we don't clobber other
         * in-flight DPCs with InterruptLock,
         * StartIoLock only valid in Half-Duplex Mode 
         */
        SendSRB(DeviceExtension, (PSRB_TYPE)Srb, DpcLock);
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
    return TRUE;
}

VOID
FORCEINLINE
HandleResponse(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSICmd cmd,
    IN PVOID InlineFuncName
    )
{
    PSRB_TYPE Srb = (PSRB_TYPE)(cmd->srb);

    #if !defined(RUN_UNCHECKED)
    ENTER_INL_FN_SRB();
    #endif

    PSRB_EXTENSION srbExt = SRB_EXTENSION(Srb);
    VirtIOSCSICmdResp *resp = &cmd->resp.cmd;
    UCHAR senseInfoBufferLength = 0;
    PVOID senseInfoBuffer = NULL;
    UCHAR srbStatus = SRB_STATUS_SUCCESS;
    ULONG srbDataTransferLen = SRB_DATA_TRANSFER_LENGTH(Srb);


    #if !defined(RUN_UNCHECKED)
    LOG_SRB_INFO_FROM_INLFN();
    #endif

    switch (resp->response) {
    case VIRTIO_SCSI_S_OK:
        SRB_SET_SCSI_STATUS(Srb, resp->status);
        srbStatus = (resp->status == SCSISTAT_GOOD) ? SRB_STATUS_SUCCESS : SRB_STATUS_ERROR;
        #if !defined(RUN_UNCHECKED)
        if (srbStatus == SRB_STATUS_SUCCESS) {
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_OK : SRB_STATUS_SUCCESS\n");
        } else {
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_OK : SRB_STATUS_ERROR\n");
        }
        #endif
        break;
    case VIRTIO_SCSI_S_UNDERRUN:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_UNDERRUN\n");
        #endif
        srbStatus = SRB_STATUS_DATA_OVERRUN;
        break;
    case VIRTIO_SCSI_S_ABORTED:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_ABORTED\n");
        #endif
        srbStatus = SRB_STATUS_ABORTED;
        break;
    case VIRTIO_SCSI_S_BAD_TARGET:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_BAD_TARGET\n");
        #endif
        srbStatus = SRB_STATUS_INVALID_TARGET_ID;
        break;
    case VIRTIO_SCSI_S_RESET:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_RESET\n");
        #endif
        srbStatus = SRB_STATUS_BUS_RESET;
        break;
    case VIRTIO_SCSI_S_BUSY:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_BUSY\n");
        #endif
        srbStatus = SRB_STATUS_BUSY;
        break;
    case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_TRANSPORT_FAILURE\n");
        #endif
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_TARGET_FAILURE:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_TARGET_FAILURE\n");
        #endif
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_NEXUS_FAILURE:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_NEXUS_FAILURE\n");
        #endif
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_FAILURE:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_FAILURE\n");
        #endif
        srbStatus = SRB_STATUS_ERROR;
        break;
    default:
        srbStatus = SRB_STATUS_ERROR;
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Unknown response %d\n", resp->response);
        #endif
        break;
    }
    if (srbStatus == SRB_STATUS_SUCCESS &&
        resp->resid &&
        srbDataTransferLen > resp->resid)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbDataTransferLen - resp->resid);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    else if (srbStatus != SRB_STATUS_SUCCESS)
    {
        SRB_GET_SENSE_INFO(Srb, senseInfoBuffer, senseInfoBufferLength);
        if (senseInfoBufferLength >= FIELD_OFFSET(SENSE_DATA, CommandSpecificInformation)) {
            RtlCopyMemory(senseInfoBuffer, resp->sense,
                min(resp->sense_len, senseInfoBufferLength));
            if (srbStatus == SRB_STATUS_ERROR) {
                srbStatus |= SRB_STATUS_AUTOSENSE_VALID;
            }
        }
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
    }
    else if (srbExt && srbExt->Xfer && srbDataTransferLen > srbExt->Xfer)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbExt->Xfer);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    SRB_SET_SRB_STATUS(Srb, srbStatus);
    CompleteRequest(DeviceExtension, Srb);

    #if !defined(RUN_UNCHECKED)
    EXIT_INL_FN_SRB();
    #endif
}

BOOLEAN
VioScsiInterrupt(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION  adaptExt = NULL;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (adaptExt->bRemoved)
    {
        return FALSE;
    }

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " IRQL (%d)\n", KeGetCurrentIrql());
    #endif

    if ((virtio_read_isr_status(&adaptExt->vdev) == 1) || adaptExt->dump_mode) {
        return ProcessQueue(DeviceExtension, VIRTIO_SCSI_REQUEST_QUEUE_0 + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET, "ProcessQueue");
    } else {
        return FALSE;
    }
}

BOOLEAN
VioScsiMSInterrupt(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageId
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BOOLEAN isInterruptServiced = FALSE;
    ULONG i;

    if (adaptExt->bRemoved)
    {
        return FALSE;
    }

    if (!adaptExt->msix_one_vector) {
        /* Each queue has its own vector, this is the fast and common case */
        return ProcessQueue(DeviceExtension, MessageId, "ProcessQueue");
    }

    /* Fall back to checking all queues */
    for (i = 0; i < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; i++) {
        if (virtqueue_has_buf(adaptExt->vq[i])) {
            isInterruptServiced |= ProcessQueue(DeviceExtension, i + VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET, "ProcessQueue");
        }
    }
    return isInterruptServiced;
}

BOOLEAN
VioScsiResetBus(
    IN PVOID DeviceExtension,
    IN ULONG PathId
    )
{
    UNREFERENCED_PARAMETER( PathId );

    return DeviceReset(DeviceExtension);
}

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(
    IN PVOID DeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PSCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG                             AdjustedMaxControlType;
    ULONG                             Index;
    PADAPTER_EXTENSION                adaptExt;
    SCSI_ADAPTER_CONTROL_STATUS       status = ScsiAdapterControlUnsuccessful;
    BOOLEAN SupportedControlTypes[17] = { 0 };

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    SupportedControlTypes[0]  = 1; //ScsiQuerySupportedControlTypes
    SupportedControlTypes[1]  = 1; //ScsiStopAdapter
    SupportedControlTypes[2]  = 1; //ScsiRestartAdapter
    SupportedControlTypes[16] = 1; //ScsiAdapterSurpriseRemoval

    switch (ControlType) {

    case ScsiQuerySupportedControlTypes: {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " ScsiQuerySupportedControlTypes\n");
        #endif
        ControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
        AdjustedMaxControlType =
            (ControlTypeList->MaxControlType < 5) ?
            ControlTypeList->MaxControlType :
            5;
        for (Index = 0; Index < AdjustedMaxControlType; Index++) {
            ControlTypeList->SupportedTypeList[Index] =
                SupportedControlTypes[Index];
        }
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiStopAdapter: {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " ScsiStopAdapter\n");
        #endif
        ShutDown(DeviceExtension);
        if (adaptExt->pmsg_affinity != NULL) {
            StorPortFreePool(DeviceExtension,
                (PVOID)adaptExt->pmsg_affinity);
            adaptExt->pmsg_affinity = NULL;
        }
        adaptExt->perfFlags = 0;
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiRestartAdapter: {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " ScsiRestartAdapter\n");
        #endif
        ShutDown(DeviceExtension);
        if (!VioScsiHwReinitialize(DeviceExtension))
        {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot reinitialize HW\n");
            #endif
            break;
        }
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiAdapterSurpriseRemoval: {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " ScsiAdapterSurpriseRemoval\n");
        #endif
        adaptExt->bRemoved = TRUE;
        status = ScsiAdapterControlSuccess;
        break;
    }
    default:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupported ControlType %d\n", ControlType);
        #endif
        break;
    }

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return status;
}

SCSI_UNIT_CONTROL_STATUS
VioScsiUnitControl(
    IN PVOID DeviceExtension,
    IN SCSI_UNIT_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PSCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG                             AdjustedMaxControlType;
    ULONG                             index;
    PADAPTER_EXTENSION                adaptExt;
    SCSI_UNIT_CONTROL_STATUS          Status = ScsiUnitControlUnsuccessful;
    BOOLEAN SupportedControlTypes[11] = { 0 };

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    SupportedControlTypes[0]  = 1; //ScsiQuerySupportedControlTypes
    SupportedControlTypes[2]  = 1; //ScsiUnitStart
    SupportedControlTypes[9]  = 1; //ScsiUnitRemove
    SupportedControlTypes[10] = 1; //ScsiUnitSurpriseRemoval

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Unit Control Type %d\n", ControlType);
    #endif
    switch (ControlType) {
        case ScsiQuerySupportedControlTypes:
            ControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
            AdjustedMaxControlType = (ControlTypeList->MaxControlType < 11) ?
                                      ControlTypeList->MaxControlType : 11;
            for (index = 0; index < AdjustedMaxControlType; index++) {
            ControlTypeList->SupportedTypeList[index] =
                                      SupportedControlTypes[index];
            }
            Status = ScsiUnitControlSuccess;
            break;
        case ScsiUnitStart:
            Status = ScsiUnitControlSuccess;
            break;
        case ScsiUnitRemove:
        case ScsiUnitSurpriseRemoval:
            ULONG QueueNumber;
            ULONG MessageId;
            STOR_LOCK_HANDLE LockHandle = { 0 };
            PSTOR_ADDR_BTL8  stor_addr = (PSTOR_ADDR_BTL8)Parameters;

            for (index = 0; index < adaptExt->num_queues; index++) {
                PREQUEST_LIST element = &adaptExt->processing_srbs[index];
                QueueNumber = index + VIRTIO_SCSI_REQUEST_QUEUE_0;
                MessageId = QUEUE_TO_MESSAGE(QueueNumber);
                VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, DpcLock, VIOSCSI_VQLOCKOP_LOCK);
                if (!IsListEmpty(&element->srb_list))
                {
                    PLIST_ENTRY entry = element->srb_list.Flink;
                    while (entry != &element->srb_list) {
                        PSRB_EXTENSION currSrbExt = CONTAINING_RECORD(entry, SRB_EXTENSION, list_entry);
                        PSCSI_REQUEST_BLOCK  currSrb = currSrbExt->Srb;
                        if (SRB_PATH_ID(currSrb) == stor_addr->Path &&
                            SRB_TARGET_ID(currSrb) == stor_addr->Target &&
                            SRB_LUN(currSrb) == stor_addr->Lun) {
                            SRB_SET_SRB_STATUS(currSrb, SRB_STATUS_NO_DEVICE);
                            CompleteRequest(DeviceExtension, (PSRB_TYPE)currSrb);
                            #if !defined(RUN_UNCHECKED)
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                                " Complete pending I/Os on Path %d Target %d Lun %d \n",
                                SRB_PATH_ID(currSrb),
                                SRB_TARGET_ID(currSrb),
                                SRB_LUN(currSrb));
                            #endif
                            element->srb_cnt--;
                        }
                    }
                }
                VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, DpcLock, VIOSCSI_VQLOCKOP_UNLOCK);
            }
            Status = ScsiUnitControlSuccess;
            break;
        default:
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupported Unit ControlType %d\n", ControlType);
            #endif
            break;
    }

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return Status;
}

BOOLEAN
VioScsiBuildIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PCDB                  cdb;
    ULONG                 i;
    ULONG                 fragLen;
    ULONG                 sgElement;
    ULONG                 sgMaxElements;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_EXTENSION        srbExt;
    PSTOR_SCATTER_GATHER_LIST sgList;
    VirtIOSCSICmd         *cmd;
    UCHAR                 TargetId;
    UCHAR                 Lun;

    cdb      = SRB_CDB(Srb);
    srbExt   = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TargetId = SRB_TARGET_ID(Srb);
    Lun      = SRB_LUN(Srb);

    if( (SRB_PATH_ID(Srb) > (UCHAR)adaptExt->num_queues) ||
        (TargetId >= adaptExt->scsi_config.max_target) ||
        (Lun >= adaptExt->scsi_config.max_lun) ||
        adaptExt->bRemoved) {
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_NO_DEVICE);
        StorPortNotification(RequestComplete,
                             DeviceExtension,
                             Srb);
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return FALSE;
    }

    #if !defined(RUN_UNCHECKED)
    LOG_SRB_INFO();
    #endif

    RtlZeroMemory(srbExt, sizeof(*srbExt));
    srbExt->Srb = Srb;
    srbExt->psgl = srbExt->vio_sg;
    srbExt->pdesc = srbExt->desc_alias;

    cmd = &srbExt->cmd;
    cmd->srb = (PVOID)Srb;
    cmd->req.cmd.lun[0] = 1;
    cmd->req.cmd.lun[1] = TargetId;
    cmd->req.cmd.lun[2] = 0;
    cmd->req.cmd.lun[3] = Lun;
    cmd->req.cmd.tag = (ULONG_PTR)(Srb);
    cmd->req.cmd.task_attr = VIRTIO_SCSI_S_SIMPLE;
    cmd->req.cmd.prio = 0;
    cmd->req.cmd.crn = 0;
    if (cdb != NULL) {
        RtlCopyMemory(cmd->req.cmd.cdb, cdb, min(VIRTIO_SCSI_CDB_SIZE, SRB_CDB_LENGTH(Srb)));
    }

    sgElement = 0;
    srbExt->psgl[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.cmd, &fragLen);
    srbExt->psgl[sgElement].length   = sizeof(cmd->req.cmd);
    sgElement++;

    sgList = StorPortGetScatterGatherList(DeviceExtension, Srb);
    if (sgList)
    {
        sgMaxElements = min((adaptExt->max_physical_breaks + 1), sgList->NumberOfElements);

        if((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) == SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < sgMaxElements; i++, sgElement++) {
                srbExt->psgl[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->psgl[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }

    srbExt->out = sgElement;
    srbExt->psgl[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.cmd, &fragLen);
    srbExt->psgl[sgElement].length = sizeof(cmd->resp.cmd);
    sgElement++;
    if (sgList)
    {
        sgMaxElements = min((adaptExt->max_physical_breaks + 1), sgList->NumberOfElements);

        if((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) != SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < sgMaxElements; i++, sgElement++) {
                srbExt->psgl[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->psgl[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }
    srbExt->in = sgElement - srbExt->out;

    if (adaptExt->resp_time)
    {
        LARGE_INTEGER counter = { 0 };
        ULONG status = STOR_STATUS_SUCCESS;
        status = StorPortQueryPerformanceCounter(DeviceExtension, NULL, &counter);
        if ( status == STOR_STATUS_SUCCESS)
        {
            srbExt->time = counter.QuadPart;
        }
        else
        {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, "SRB 0x%p StorPortQueryPerformanceCounter failed with status  0x%lx\n", Srb, status);
            #endif
        }
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
    return TRUE;
}

BOOLEAN
FORCEINLINE
ProcessQueue(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageId,
    IN PVOID InlineFuncName
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_INL_FN();
    #endif

    PVirtIOSCSICmd      cmd;
    PVirtIOSCSIEventNode evtNode;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    PSRB_TYPE           Srb = NULL;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Processing VirtIO Queue : %lu \n", MESSAGE_TO_QUEUE(MessageId));
    #endif

    if (MessageId >= QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0))
    {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Dispatching to Request Queue...\n");
        #endif
        DispatchQueue(DeviceExtension, MessageId, "DispatchQueue");
        #if !defined(RUN_UNCHECKED)
        EXIT_INL_FN();
        #endif
        return TRUE;
    }
    if ((MessageId == 0) && (VIRTIO_SCSI_MSI_CONTROL_Q_OFFSET != 0))
    {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " MSI-X Vector 0 [MessageId = 0] is unused by HBA. Returning without further processing.\n");
        #endif
        #if !defined(RUN_UNCHECKED)
        EXIT_INL_FN();
        #endif
        return TRUE;
    }
    if (MessageId == QUEUE_TO_MESSAGE(VIRTIO_SCSI_CONTROL_QUEUE))
    {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Processing Control Queue...\n");
        #endif
        if (adaptExt->tmf_infly)
        {
            while((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE], &len)) != NULL)
            {
                VirtIOSCSICtrlTMFResp *resp;
                Srb = (PSRB_TYPE)(cmd->srb);
                ASSERT(Srb == (PSRB_TYPE)&adaptExt->tmf_cmd.Srb);
                resp = &cmd->resp.tmf;
                switch(resp->response) {
                    case VIRTIO_SCSI_S_OK:
                    case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                        break;
                    default:
                        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                        RhelDbgPrint(TRACE_LEVEL_ERROR, " Unknown ERROR response %d\n", resp->response);
                        #endif
                        ASSERT(0);
                        break;
              }
              StorPortResume(DeviceExtension);
           }
           adaptExt->tmf_infly = FALSE;
        }
        #if !defined(RUN_UNCHECKED)
        EXIT_INL_FN();
        #endif
        return TRUE;
    }
    if (MessageId == QUEUE_TO_MESSAGE(VIRTIO_SCSI_EVENTS_QUEUE)) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Processing Events Queue...\n");
        #endif
        while((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) != NULL) {
            PVirtIOSCSIEvent evt = &evtNode->event;
            switch (evt->event) {
                case VIRTIO_SCSI_T_NO_EVENT:
                    break;
                case VIRTIO_SCSI_T_TRANSPORT_RESET:
                    TransportReset(DeviceExtension, evt);
                    break;
                case VIRTIO_SCSI_T_PARAM_CHANGE:
                    ParamChange(DeviceExtension, evt);
                    break;
                default:
                    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                    RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupport virtio scsi event %x\n", evt->event);
                    #endif
                    break;
           }
           SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }
        #if !defined(RUN_UNCHECKED)
        EXIT_INL_FN();
        #endif
        return TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_INL_FN();
    #endif
    return FALSE;
}

BOOLEAN
FORCEINLINE
DispatchQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageId,
    IN PVOID InlineFuncName
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_INL_FN();
    #endif
    
    PADAPTER_EXTENSION  adaptExt;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    
    if (!adaptExt->dump_mode && adaptExt->dpc_ok) {
        NT_ASSERT(MessageId >= QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0));
        if (StorPortIssueDpc(DeviceExtension,
            &adaptExt->dpc[MessageId - QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0)],
            ULongToPtr(MessageId),
            ULongToPtr(MessageId))) {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_DPC, " The request to queue a DPC was successful.\n");
            EXIT_INL_FN();
            //EXIT_FN();
            #endif
            return TRUE;
        } else {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_DPC, " The request to queue a DPC was NOT successful. It may already be queued elsewhere.\n");
            EXIT_INL_FN();
            //EXIT_FN();
            #endif
            return FALSE;
        }
    }
    ProcessBuffer(DeviceExtension, MessageId, InterruptLock);
    #if !defined(RUN_UNCHECKED)
    EXIT_INL_FN();
    #endif
    return TRUE;
}

VOID
ProcessBuffer(
    IN PVOID DeviceExtension,
    IN ULONG MessageId,
    IN STOR_SPINLOCK LockMode
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PVirtIOSCSICmd      cmd;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG               QueueNumber = MESSAGE_TO_QUEUE(MessageId);
    STOR_LOCK_HANDLE    LockHandle = { 0 };
    struct virtqueue    *vq;
    PSRB_TYPE           Srb = NULL;
    PSRB_EXTENSION      srbExt = NULL;
    ULONG               qty_req_vq;
    PREQUEST_LIST       element;
    ULONG               vq_req_idx;


    qty_req_vq = adaptExt->num_queues;
    if (QueueNumber >= (qty_req_vq + VIRTIO_SCSI_REQUEST_QUEUE_0)) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_VQ, " Modulo assignment required for QueueNumber as it exceeds the number of virtqueues available.\n");
        #endif
        QueueNumber %= qty_req_vq;
    }
    vq_req_idx = QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0;
    element = &adaptExt->processing_srbs[vq_req_idx];

    vq = adaptExt->vq[QueueNumber];

    VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, LockMode, VIOSCSI_VQLOCKOP_LOCK);
    do {
        virtqueue_disable_cb(vq);
        while ((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(vq, &len)) != NULL) {
            PLIST_ENTRY le = NULL;
            BOOLEAN bFound = FALSE;

            Srb = (PSRB_TYPE)(cmd->srb);
            if (!Srb)
                continue;

            srbExt = SRB_EXTENSION(Srb);
            for (le = element->srb_list.Flink; le != &element->srb_list && !bFound; le = le->Flink)
            {
                PSRB_EXTENSION currSrbExt = CONTAINING_RECORD(le, SRB_EXTENSION, list_entry);
                PSCSI_REQUEST_BLOCK  currSrb = currSrbExt->Srb;

                if (currSrbExt == srbExt && (PSRB_TYPE)currSrb == Srb)
                {
                    RemoveEntryList(le);
                    bFound = TRUE;
                    element->srb_cnt--;
                    break;
                }
            }
            if (bFound) {
                HandleResponse(DeviceExtension, cmd, "HandleResponse");
            }
        }
    } while (!virtqueue_enable_cb(vq));
    VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, LockMode, VIOSCSI_VQLOCKOP_UNLOCK);

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

VOID
VioScsiCompleteDpcRoutine(
    IN PSTOR_DPC  Dpc,
    IN PVOID Context,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    ULONG MessageId;

    MessageId = PtrToUlong(SystemArgument1);
    ProcessBuffer(Context, MessageId, DpcLock);

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

VOID
CompletePendingRequestsOnReset(
    IN PVOID DeviceExtension,
    IN STOR_SPINLOCK LockMode
    )
{
    PADAPTER_EXTENSION adaptExt;
    ULONG QueueNumber;
    ULONG MessageId;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (!adaptExt->reset_in_progress)
    {
        adaptExt->reset_in_progress = TRUE;
        StorPortPause(DeviceExtension, 10);
        DeviceReset(DeviceExtension);

        for (ULONG index = 0; index < adaptExt->num_queues; index++) {
            PREQUEST_LIST element = &adaptExt->processing_srbs[index];
            STOR_LOCK_HANDLE    LockHandle = { 0 };
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL, " queue %d cnt %d\n", index, element->srb_cnt);
            #endif
            QueueNumber = index + VIRTIO_SCSI_REQUEST_QUEUE_0;
            MessageId = QUEUE_TO_MESSAGE(QueueNumber);
            VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, LockMode, VIOSCSI_VQLOCKOP_LOCK);
            while (!IsListEmpty(&element->srb_list)) {
                PLIST_ENTRY entry = RemoveHeadList(&element->srb_list);
                if (entry) {
                    PSRB_EXTENSION currSrbExt = CONTAINING_RECORD(entry, SRB_EXTENSION, list_entry);
                    PSCSI_REQUEST_BLOCK  currSrb = currSrbExt->Srb;
                    if (currSrb) {
                        SRB_SET_SRB_STATUS(currSrb, SRB_STATUS_BUS_RESET);
                        CompleteRequest(DeviceExtension, (PSRB_TYPE)currSrb);
                        element->srb_cnt--;
                    }
                }
            }
            if (element->srb_cnt) {
                element->srb_cnt = 0;
            }
            VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, LockMode, VIOSCSI_VQLOCKOP_UNLOCK);
        }
        StorPortResume(DeviceExtension);
    }
    else {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " Reset is already in progress, doing nothing.\n");
        #endif
    }
    adaptExt->reset_in_progress = FALSE;
}

UCHAR
VioScsiProcessPnP(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION      adaptExt;
    PSCSI_PNP_REQUEST_BLOCK pnpBlock;
    ULONG                   SrbPnPFlags;
    ULONG                   PnPAction;
    UCHAR                   SrbStatus;

    adaptExt  = (PADAPTER_EXTENSION)DeviceExtension;
    pnpBlock  = (PSCSI_PNP_REQUEST_BLOCK)Srb;
    SrbStatus = SRB_STATUS_SUCCESS;
    SRB_GET_PNP_INFO(Srb, SrbPnPFlags, PnPAction);
    switch (PnPAction) {
        case StorQueryCapabilities:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                " StorQueryCapabilities on %d::%d::%d\n",
                SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb));
            #endif
            if (((SrbPnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST) == 0) ||
                (SRB_DATA_TRANSFER_LENGTH(Srb) >= sizeof(STOR_DEVICE_CAPABILITIES))) {
                PSTOR_DEVICE_CAPABILITIES devCap =
                    (PSTOR_DEVICE_CAPABILITIES)SRB_DATA_BUFFER(Srb);
                RtlZeroMemory(devCap, sizeof(*devCap));
                devCap->Removable = 1;
                devCap->SurpriseRemovalOK = 1;
            }
            break;
        case StorRemoveDevice:
        case StorSurpriseRemoval:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL,
                " Adapter Removal happens on %d::%d::%d\n",
                SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb));
            #endif
            adaptExt->bRemoved = TRUE;
            break;
        default:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL,
                " Unsupported PnPAction SrbPnPFlags = %d, PnPAction = %d\n",
                SrbPnPFlags, PnPAction);
            #endif
            SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return SrbStatus;
}

BOOLEAN
FORCEINLINE
PreProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN PVOID InlineFuncName
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_INL_FN_SRB();
    #endif

    PADAPTER_EXTENSION adaptExt;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    switch (SRB_FUNCTION(Srb)) {
        case SRB_FUNCTION_PNP:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Pre-Processor detected SRB_FUNCTION_PNP. Executing VioScsiProcessPnP()...\n");
            #endif
            SRB_SET_SRB_STATUS(Srb, VioScsiProcessPnP(DeviceExtension, Srb));
            #if !defined(RUN_UNCHECKED)
            EXIT_INL_FN_SRB();
            #endif
            return TRUE;

        case SRB_FUNCTION_POWER:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Pre-Processor detected SRB_FUNCTION_POWER. Setting SRB_STATUS_SUCCESS.\n");
            #endif
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            #if !defined(RUN_UNCHECKED)
            EXIT_INL_FN_SRB();
            #endif
            return TRUE;

        case SRB_FUNCTION_RESET_BUS:
        case SRB_FUNCTION_RESET_DEVICE:
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> SRB_FUNCTION_RESET_LOGICAL_UNIT Target (%d::%d::%d), SRB 0x%p\n", SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb), Srb);
            #endif
            switch (adaptExt->action_on_reset) {
                case VioscsiResetCompleteRequests:
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Completing all pending SRBs\n");
                    #endif
                    CompletePendingRequestsOnReset(DeviceExtension, DpcLock);
                    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
                    #if !defined(RUN_UNCHECKED)
                    EXIT_INL_FN_SRB();
                    #endif
                    return TRUE;
                case VioscsiResetDoNothing:
                    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Doing nothing with all pending SRBs\n");
                    EXIT_INL_FN_SRB();
                    #endif
                    return TRUE;
                case VioscsiResetBugCheck:
                    KeBugCheckEx(0xDEADDEAD, (ULONG_PTR)Srb, SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb));
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Let's bugcheck due to this reset event\n");
                    EXIT_INL_FN_SRB();
                    #endif
                    return TRUE;
            }
        case SRB_FUNCTION_WMI:
            // FIXME???
            // What if VioScsiWmiSrb() fails?
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Pre-Processor detected SRB_FUNCTION_WMI. Executing VioScsiWmiSrb()...\n");
            #endif
            VioScsiWmiSrb(DeviceExtension, Srb);
            #if !defined(RUN_UNCHECKED)
            EXIT_INL_FN_SRB();
            #endif
            return TRUE;
        case SRB_FUNCTION_IO_CONTROL:
            // FIXME???
            // What if func() fails?
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Pre-Processor detected SRB_FUNCTION_IO_CONTROL. Executing VioScsiIoControl()...\n");
            #endif
            VioScsiIoControl(DeviceExtension, Srb);
            #if !defined(RUN_UNCHECKED)
            EXIT_INL_FN_SRB();
            #endif
            return TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Pre-Processor did not detect any SRB_FUNCTION calls.\n");
    EXIT_INL_FN_SRB();
    #endif
    return FALSE;
}

VOID
FORCEINLINE
PostProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN PVOID InlineFuncName
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_INL_FN_SRB();
    #endif

    PCDB                  cdb = NULL;
    PADAPTER_EXTENSION    adaptExt = NULL;
    PSRB_EXTENSION        srbExt = NULL;

    if (SRB_FUNCTION(Srb) != SRB_FUNCTION_EXECUTE_SCSI) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Post-Processor detected this is NOT a SRB_FUNCTION_EXECUTE_SCSI.\n");
        EXIT_INL_FN_SRB();
        #endif
        return;
    }
    cdb = SRB_CDB(Srb);
    if (!cdb)
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Post-Processor detected this is NOT a Command Descriptor Block (CDB).\n");
        EXIT_INL_FN_SRB();
        #endif
        return;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    switch (cdb->CDB6GENERIC.OperationCode)
    {
        case SCSIOP_READ_CAPACITY:
        case SCSIOP_READ_CAPACITY16:
            break;
        case SCSIOP_INQUIRY:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Post-Processor detected SCSIOP_INQUIRY. Saving and Patching Inquiry Data...\n");
            #endif
            VioScsiSaveInquiryData(DeviceExtension, Srb);
            VioScsiPatchInquiryData(DeviceExtension, Srb);
            if (!StorPortSetDeviceQueueDepth( DeviceExtension, SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb), adaptExt->queue_depth)) {
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_ERROR, " StorPortSetDeviceQueueDepth(%p, %x) failed.\n", DeviceExtension, adaptExt->queue_depth);
                EXIT_INL_FN_SRB();
                #endif
           }
            break;
        default:
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Post-Processor did NOT detect any CDB6GENERIC Operation Codes in the Command Descriptor Block (CDB).\n");
            #endif
            break;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_INL_FN_SRB();
    #endif
}

VOID
CompleteRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PADAPTER_EXTENSION    adaptExt = NULL;
    PSRB_EXTENSION        srbExt = NULL;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PostProcessRequest(DeviceExtension, Srb, "PostProcessRequest");

    if (adaptExt->resp_time)
    {
        srbExt = SRB_EXTENSION(Srb);
        if (srbExt->time != 0)
        {
            LARGE_INTEGER counter = { 0 };
            LARGE_INTEGER freq = { 0 };
            ULONG status = StorPortQueryPerformanceCounter(DeviceExtension, &freq, &counter);

            if (status == STOR_STATUS_SUCCESS)
            {
                ULONGLONG time_msec = ((counter.QuadPart - srbExt->time) * 1000) / freq.QuadPart;
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, "time_msec %I64d Start %llu End %llu Freq %llu\n",
                      time_msec, srbExt->time, counter.QuadPart, freq.QuadPart);
                #endif
                if (time_msec >= adaptExt->resp_time)
                {
                    UCHAR OpCode = SRB_CDB(Srb)->CDB6GENERIC.OperationCode;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_WARNING, "Response Time SRB 0x%p : time %I64d (%lu) : length %d : OpCode 0x%x (%s)\n", 
                        Srb, time_msec, SRB_GET_TIMEOUTVALUE(Srb) * 1000, SRB_DATA_TRANSFER_LENGTH(Srb),
                        OpCode, DbgGetScsiOpStr(OpCode));
                    DbgPrint("Response Time SRB 0x%p : time %I64d (%lu) : length %d : OpCode 0x%x (%s)\n",
                        Srb, time_msec, SRB_GET_TIMEOUTVALUE(Srb) * 1000, SRB_DATA_TRANSFER_LENGTH(Srb),
                        OpCode, DbgGetScsiOpStr(OpCode));
                    #endif
                }
            }
            else
            {
                #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                RhelDbgPrint(TRACE_LEVEL_ERROR, "SRB 0x%p StorPortQueryPerformanceCounter failed with status  0x%lx\n", Srb, status);
                #endif
            }
        }
    }
    StorPortNotification(RequestComplete,
                         DeviceExtension,
                         Srb);
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " StorPort was notified the request is complete.\n");
    EXIT_FN_SRB();
    #endif
}

VOID
LogError(
    IN PVOID DeviceExtension,
    IN ULONG ErrorCode,
    IN ULONG UniqueId
    )
{
    STOR_LOG_EVENT_DETAILS logEvent;
    ULONG sz = 0;
    RtlZeroMemory( &logEvent, sizeof(logEvent) );
    logEvent.InterfaceRevision         = STOR_CURRENT_LOG_INTERFACE_REVISION;
    logEvent.Size                      = sizeof(logEvent);
    logEvent.EventAssociation          = StorEventAdapterAssociation;
    logEvent.StorportSpecificErrorCode = TRUE;
    logEvent.ErrorCode                 = ErrorCode;
    logEvent.DumpDataSize              = sizeof(UniqueId);
    logEvent.DumpData                  = &UniqueId;
    StorPortLogSystemEvent( DeviceExtension, &logEvent, &sz );
}

VOID
TransportReset(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    UCHAR TargetId = evt->lun[1];
    UCHAR Lun = (evt->lun[2] << 8) | evt->lun[3];

    switch (evt->reason) {
        case VIRTIO_SCSI_EVT_RESET_RESCAN:
            StorPortNotification(BusChangeDetected, DeviceExtension, 0);
            break;
        case VIRTIO_SCSI_EVT_RESET_REMOVED:
            StorPortNotification(BusChangeDetected, DeviceExtension, 0);
            break;
        default:
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " <--> Unsupport virtio scsi event reason 0x%x\n", evt->reason);
            #endif
            break;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

VOID
ParamChange(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    UCHAR TargetId = evt->lun[1];
    UCHAR Lun = (evt->lun[2] << 8) | evt->lun[3];
    UCHAR AdditionalSenseCode = (UCHAR)(evt->reason & 255);
    UCHAR AdditionalSenseCodeQualifier = (UCHAR)(evt->reason >> 8);

    if (AdditionalSenseCode == SCSI_ADSENSE_PARAMETERS_CHANGED &&
       (AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED ||
        AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED ||
        AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED))
    {
        StorPortNotification( BusChangeDetected, DeviceExtension, 0);
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

VOID
VioScsiWmiInitialize(
    IN PVOID DeviceExtension
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION    adaptExt;
    PSCSI_WMILIB_CONTEXT WmiLibContext;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    WmiLibContext = (PSCSI_WMILIB_CONTEXT)(&(adaptExt->WmiLibContext));

    WmiLibContext->GuidList = VioScsiGuidList;
    WmiLibContext->GuidCount = VioScsiGuidCount;
    WmiLibContext->QueryWmiRegInfo = VioScsiQueryWmiRegInfo;
    WmiLibContext->QueryWmiDataBlock = VioScsiQueryWmiDataBlock;
    WmiLibContext->SetWmiDataItem = NULL;
    WmiLibContext->SetWmiDataBlock = NULL;
    WmiLibContext->ExecuteWmiMethod = VioScsiExecuteWmiMethod;
    WmiLibContext->WmiFunctionControl = NULL;

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

VOID
VioScsiWmiSrb(
    IN PVOID DeviceExtension,
    IN OUT PSRB_TYPE Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    UCHAR status;
    SCSIWMI_REQUEST_CONTEXT requestContext = {0};
    ULONG retSize;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_WMI_DATA pSrbWmi = SRB_WMI_DATA(Srb);

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    ASSERT(SRB_FUNCTION(Srb) == SRB_FUNCTION_WMI);
    ASSERT(SRB_LENGTH(Srb)  == sizeof(SCSI_WMI_REQUEST_BLOCK));
    ASSERT(SRB_DATA_TRANSFER_LENGTH(Srb) >= sizeof(ULONG));
    ASSERT(SRB_DATA_BUFFER(Srb));

    if (!pSrbWmi)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;
    if (!(pSrbWmi->WMIFlags & SRB_WMI_FLAGS_ADAPTER_REQUEST))
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
    }
    else
    {
        requestContext.UserContext = Srb;
        (VOID)ScsiPortWmiDispatchFunction(&adaptExt->WmiLibContext,
                                                pSrbWmi->WMISubFunction,
                                                DeviceExtension,
                                                &requestContext,
                                                pSrbWmi->DataPath,
                                                SRB_DATA_TRANSFER_LENGTH(Srb),
                                                SRB_DATA_BUFFER(Srb));

        retSize =  ScsiPortWmiGetReturnSize(&requestContext);
        status =  ScsiPortWmiGetReturnStatus(&requestContext);

        SRB_SET_DATA_TRANSFER_LENGTH(Srb, retSize);
        SRB_SET_SRB_STATUS(Srb, status);
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
}

VOID
VioScsiIoControl(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PSRB_IO_CONTROL srbControl;
    PVOID           srbDataBuffer = SRB_DATA_BUFFER(Srb);
    PADAPTER_EXTENSION    adaptExt;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    srbControl = (PSRB_IO_CONTROL)srbDataBuffer;

    switch (srbControl->ControlCode) {
        case IOCTL_SCSI_MINIPORT_NOT_QUORUM_CAPABLE:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_ERROR);
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> Signature = %02x %02x %02x %02x %02x %02x %02x %02x\n",
                srbControl->Signature[0], srbControl->Signature[1], srbControl->Signature[2], srbControl->Signature[3],
                srbControl->Signature[4], srbControl->Signature[5], srbControl->Signature[6], srbControl->Signature[7]);
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> IOCTL_SCSI_MINIPORT_NOT_QUORUM_CAPABLE\n");
            #endif
            break;
        case IOCTL_SCSI_MINIPORT_FIRMWARE:
            FirmwareRequest(DeviceExtension, Srb);
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> IOCTL_SCSI_MINIPORT_FIRMWARE\n");
            #endif
            break;
        default:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_INVALID_REQUEST);
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> Unsupported control code 0x%x\n", srbControl->ControlCode);
            #endif
            break;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
}

UCHAR
ParseIdentificationDescr(
    IN PVOID  DeviceExtension,
    IN PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr,
    IN UCHAR PageLength
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION    adaptExt;
    UCHAR CodeSet = 0;
    UCHAR IdentifierType = 0;
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    if (IdentificationDescr) {
        CodeSet = IdentificationDescr->CodeSet;//(UCHAR)(((PCHAR)IdentificationDescr)[0]);
        IdentifierType = IdentificationDescr->IdentifierType;//(UCHAR)(((PCHAR)IdentificationDescr)[1]);
        switch (IdentifierType) {
        case VioscsiVpdIdentifierTypeVendorSpecific: {
            if (CodeSet == VioscsiVpdCodeSetAscii) {
                if (IdentificationDescr->IdentifierLength > 0 && adaptExt->ser_num == NULL) {
                    int ln = min(64, IdentificationDescr->IdentifierLength);
                    ULONG Status =
                        StorPortAllocatePool(DeviceExtension,
                            ln + 1,
                            VIOSCSI_POOL_TAG,
                            (PVOID*)&adaptExt->ser_num);
                    if (NT_SUCCESS(Status)) {
                        StorPortMoveMemory(adaptExt->ser_num, IdentificationDescr->Identifier, ln);
                        adaptExt->ser_num[ln] = '\0';
                        #if !defined(RUN_UNCHECKED)
                        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " serial number %s\n", adaptExt->ser_num);
                        #endif
                    }
                }
            }
        }
        break;
        case VioscsiVpdIdentifierTypeFCPHName: {
            if ((CodeSet == VioscsiVpdCodeSetBinary) && (IdentificationDescr->IdentifierLength == sizeof(ULONGLONG))) {
                REVERSE_BYTES_QUAD(&adaptExt->wwn, IdentificationDescr->Identifier);
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " wwn %llu\n", (ULONGLONG)adaptExt->wwn);
                #endif
            }
        }
        break;
        case VioscsiVpdIdentifierTypeFCTargetPortPHName: {
            if ((CodeSet == VioscsiVpdCodeSetSASBinary) && (IdentificationDescr->IdentifierLength == sizeof(ULONGLONG))) {
                REVERSE_BYTES_QUAD(&adaptExt->port_wwn, IdentificationDescr->Identifier);
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " port wwn %llu\n", (ULONGLONG)adaptExt->port_wwn);
                #endif
            }
        }
        break;
        case VioscsiVpdIdentifierTypeFCTargetPortRelativeTargetPort: {
            if ((CodeSet == VioscsiVpdCodeSetSASBinary) && (IdentificationDescr->IdentifierLength == sizeof(ULONG))) {
                REVERSE_BYTES(&adaptExt->port_idx, IdentificationDescr->Identifier);
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " port index %lu\n", (ULONG)adaptExt->port_idx);
                #endif
            }
        }
        break;
        default:
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupported IdentifierType = %x!\n", IdentifierType);
            #endif
            break;
        }
        #if !defined(RUN_UNCHECKED)
        EXIT_FN();
        #endif
        return IdentificationDescr->IdentifierLength;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return 0;
}

VOID
VioScsiSaveInquiryData(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PVOID           dataBuffer;
    PADAPTER_EXTENSION    adaptExt;
    PCDB cdb;
    ULONG dataLen;
    UCHAR SrbStatus = SRB_STATUS_SUCCESS;

    if (!Srb)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;

    cdb  = SRB_CDB(Srb);

    if (!cdb)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;

    SRB_GET_SCSI_STATUS(Srb, SrbStatus);
    if (SrbStatus == SRB_STATUS_ERROR)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    dataBuffer = SRB_DATA_BUFFER(Srb);
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    if (cdb->CDB6INQUIRY3.EnableVitalProductData == 1) {
        switch (cdb->CDB6INQUIRY3.PageCode) {
            case VPD_SERIAL_NUMBER: {
                PVPD_SERIAL_NUMBER_PAGE SerialPage;
                SerialPage = (PVPD_SERIAL_NUMBER_PAGE)dataBuffer;
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VPD_SERIAL_NUMBER PageLength = %d\n", SerialPage->PageLength);
                #endif
                if (SerialPage->PageLength > 0 && adaptExt->ser_num == NULL) {
                    int ln = min(64, SerialPage->PageLength);
                    ULONG Status =
                        StorPortAllocatePool(DeviceExtension,
                            ln + 1,
                            VIOSCSI_POOL_TAG,
                            (PVOID*)&adaptExt->ser_num);
                    if (NT_SUCCESS(Status)) {
                        StorPortMoveMemory(adaptExt->ser_num, SerialPage->SerialNumber, ln);
                        adaptExt->ser_num[ln] = '\0';
                        #if !defined(RUN_UNCHECKED)
                        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " serial number %s\n", adaptExt->ser_num);
                        #endif
                    }
                }
            }
            break;
            case VPD_DEVICE_IDENTIFIERS: {
                PVPD_IDENTIFICATION_PAGE IdentificationPage;
                PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr;
                UCHAR PageLength = 0;
                IdentificationPage = (PVPD_IDENTIFICATION_PAGE)dataBuffer;
                PageLength = IdentificationPage->PageLength;
                if (PageLength >= sizeof(VPD_IDENTIFICATION_DESCRIPTOR)) {
                    UCHAR IdentifierLength = 0;
                    IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)IdentificationPage->Descriptors;
                    do {
                        UCHAR offset = 0;
                        IdentifierLength = ParseIdentificationDescr(DeviceExtension, IdentificationDescr, PageLength);
                        offset = sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + IdentifierLength;
                        PageLength -= min(PageLength, offset);
                        IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)((ULONG_PTR)IdentificationDescr + offset);
                    } while (PageLength);
                }
            }
            break;
        }
    }
    else if (cdb->CDB6INQUIRY3.PageCode == VPD_SUPPORTED_PAGES) {
        PINQUIRYDATA InquiryData = (PINQUIRYDATA)dataBuffer;
        if (InquiryData && dataLen) {
            CopyBufferToAnsiString(adaptExt->ven_id, InquiryData->VendorId, ' ', sizeof(InquiryData->VendorId));
            CopyBufferToAnsiString(adaptExt->prod_id, InquiryData->ProductId, ' ', sizeof(InquiryData->ProductId));
            CopyBufferToAnsiString(adaptExt->rev_id, InquiryData->ProductRevisionLevel, ' ',sizeof(InquiryData->ProductRevisionLevel));
        }
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
}

VOID
VioScsiPatchInquiryData(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PVOID           dataBuffer;
    PADAPTER_EXTENSION    adaptExt;
    PCDB cdb;
    ULONG dataLen;
    UCHAR SrbStatus = SRB_STATUS_SUCCESS;

    if (!Srb)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;

    cdb = SRB_CDB(Srb);

    if (!cdb)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;

    SRB_GET_SCSI_STATUS(Srb, SrbStatus);
    if (SrbStatus == SRB_STATUS_ERROR)
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    dataBuffer = SRB_DATA_BUFFER(Srb);
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    if (cdb->CDB6INQUIRY3.EnableVitalProductData == 1) {
        switch (cdb->CDB6INQUIRY3.PageCode) {
            case VPD_DEVICE_IDENTIFIERS: {
                PVPD_IDENTIFICATION_PAGE IdentificationPage;
                PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr;
                UCHAR PageLength = 0;
                IdentificationPage = (PVPD_IDENTIFICATION_PAGE)dataBuffer;
                PageLength = IdentificationPage->PageLength;
                if (dataLen >= (sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + sizeof(VPD_IDENTIFICATION_PAGE) + 8) &&
                    PageLength <= sizeof(VPD_IDENTIFICATION_PAGE)) {
                    UCHAR IdentifierLength = 0;
                    IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)IdentificationPage->Descriptors;
                    if (IdentificationDescr->IdentifierLength == 0)
                    {
                        IdentificationDescr->CodeSet = VpdCodeSetBinary;
                        IdentificationDescr->IdentifierType = VpdIdentifierTypeEUI64;
                        IdentificationDescr->IdentifierLength = 8;
                        IdentificationDescr->Identifier[0] = (adaptExt->system_io_bus_number >> 12) & 0xF;
                        IdentificationDescr->Identifier[1] = (adaptExt->system_io_bus_number >> 8) & 0xF;
                        IdentificationDescr->Identifier[2] = (adaptExt->system_io_bus_number >> 4) & 0xF;
                        IdentificationDescr->Identifier[3] = adaptExt->system_io_bus_number & 0xF;
                        IdentificationDescr->Identifier[4] = (adaptExt->slot_number >> 12) & 0xF;
                        IdentificationDescr->Identifier[5] = (adaptExt->slot_number >> 8) & 0xF;
                        IdentificationDescr->Identifier[6] = (adaptExt->slot_number >> 4) & 0xF;
                        IdentificationDescr->Identifier[7] = adaptExt->slot_number & 0xF;
                        IdentificationPage->PageLength = sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + IdentificationDescr->IdentifierLength;
                        SRB_SET_DATA_TRANSFER_LENGTH(Srb, (sizeof(VPD_IDENTIFICATION_PAGE) +
                            IdentificationPage->PageLength));
                    }
                }
            }
            break;
        }
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
}

BOOLEAN
VioScsiQueryWmiDataBlock(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG OutBufferSize,
    OUT PUCHAR Buffer
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    ULONG size = 0;
    UCHAR status = SRB_STATUS_SUCCESS;
    PADAPTER_EXTENSION    adaptExt;

    adaptExt = (PADAPTER_EXTENSION)Context;

    UNREFERENCED_PARAMETER(InstanceIndex);

    switch (GuidIndex)
    {
        case VIOSCSI_SETUP_GUID_INDEX:
        {
            size = VioScsiExtendedInfo_SIZE;
            if (OutBufferSize < size)
            {
                status = SRB_STATUS_DATA_OVERRUN;
                break;
            }

            VioScsiReadExtendedData(Context,
                                     Buffer);
            *InstanceLengthArray = size;
            status = SRB_STATUS_SUCCESS;
        }
        break;
        case VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX:
        {
            PMS_SM_AdapterInformationQuery pOutBfr = (PMS_SM_AdapterInformationQuery)Buffer;
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_WARNING, " --> VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX\n");
            #endif
            size = sizeof(MS_SM_AdapterInformationQuery);
            if (OutBufferSize < size)
            {
                status = SRB_STATUS_DATA_OVERRUN;
                break;
            }

            RtlZeroMemory(pOutBfr, size);
            pOutBfr->UniqueAdapterId = adaptExt->hba_id;
            pOutBfr->HBAStatus = HBA_STATUS_OK;
            pOutBfr->NumberOfPorts = 1;
            pOutBfr->VendorSpecificID = VENDORID | (PRODUCTID << 16);
            CopyUnicodeString(pOutBfr->Manufacturer, MANUFACTURER, sizeof(pOutBfr->Manufacturer));
            if (adaptExt->ser_num)
            {
                CopyAnsiToUnicodeString(pOutBfr->SerialNumber, adaptExt->ser_num, sizeof(pOutBfr->SerialNumber));
            }
            else
            {
                CopyUnicodeString(pOutBfr->SerialNumber, SERIALNUMBER, sizeof(pOutBfr->SerialNumber));
            }
            CopyUnicodeString(pOutBfr->Model, MODEL, sizeof(pOutBfr->Model));
            CopyUnicodeString(pOutBfr->ModelDescription, MODELDESCRIPTION, sizeof(pOutBfr->ModelDescription));
            CopyUnicodeString(pOutBfr->HardwareVersion, HARDWAREVERSION, sizeof(pOutBfr->ModelDescription));
            CopyUnicodeString(pOutBfr->DriverVersion, DRIVERVERSION, sizeof(pOutBfr->DriverVersion));
            CopyUnicodeString(pOutBfr->OptionROMVersion, OPTIONROMVERSION, sizeof(pOutBfr->OptionROMVersion));
            CopyAnsiToUnicodeString(pOutBfr->FirmwareVersion, adaptExt->rev_id, sizeof(pOutBfr->FirmwareVersion));
            CopyUnicodeString(pOutBfr->DriverName, DRIVERNAME, sizeof(pOutBfr->DriverName));
            CopyUnicodeString(pOutBfr->HBASymbolicName, HBASYMBOLICNAME, sizeof(pOutBfr->HBASymbolicName));
            CopyUnicodeString(pOutBfr->RedundantFirmwareVersion, REDUNDANTFIRMWAREVERSION, sizeof(pOutBfr->RedundantFirmwareVersion));
            CopyUnicodeString(pOutBfr->RedundantOptionROMVersion, REDUNDANTOPTIONROMVERSION, sizeof(pOutBfr->RedundantOptionROMVersion));
            CopyUnicodeString(pOutBfr->MfgDomain, MFRDOMAIN, sizeof(pOutBfr->MfgDomain));

            *InstanceLengthArray = size;
            status = SRB_STATUS_SUCCESS;
        }
        break;
        case VIOSCSI_MS_PORT_INFORM_GUID_INDEX:
        {
            size = sizeof(ULONG);
            if (OutBufferSize < size)
            {
                status = SRB_STATUS_DATA_OVERRUN;
                #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                RhelDbgPrint(TRACE_LEVEL_WARNING, " --> VIOSCSI_MS_PORT_INFORM_GUID_INDEX out buffer too small %d %d\n", OutBufferSize, size);
                #endif
                break;
            }
            *InstanceLengthArray = size;
            status = SRB_STATUS_SUCCESS;
        }
        break;
        default:
        {
            status = SRB_STATUS_ERROR;
        }
    }

    ScsiPortWmiPostProcess(RequestContext,
                           status,
                           size);

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return TRUE;
}

UCHAR
VioScsiExecuteWmiMethod(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG MethodId,
    IN ULONG InBufferSize,
    IN ULONG OutBufferSize,
    IN OUT PUCHAR Buffer
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION      adaptExt = (PADAPTER_EXTENSION)Context;
    ULONG                   size = 0;
    UCHAR                   status = SRB_STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(InstanceIndex);

    switch (GuidIndex)
    {
        case VIOSCSI_SETUP_GUID_INDEX:
        {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> VIOSCSI_SETUP_GUID_INDEX ERROR\n");
            #endif
        }
        break;
        case VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX:
        {
            PMS_SM_AdapterInformationQuery pOutBfr = (PMS_SM_AdapterInformationQuery)Buffer;
            pOutBfr;
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX ERROR\n");
            #endif
        }
        break;
        case VIOSCSI_MS_PORT_INFORM_GUID_INDEX:
        {
            switch (MethodId)
            {
                case SM_GetPortType:
                {
                    PSM_GetPortType_IN  pInBfr = (PSM_GetPortType_IN)Buffer;
                    PSM_GetPortType_OUT pOutBfr = (PSM_GetPortType_OUT)Buffer;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPortType\n");
                    #endif
                    size = SM_GetPortType_OUT_SIZE;
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetPortType_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                    pOutBfr->HBAStatus = HBA_STATUS_OK;
                    pOutBfr->PortType = HBA_PORTTYPE_SASDEVICE;
                }
                break;
                case SM_GetAdapterPortAttributes:
                {
                    PSM_GetAdapterPortAttributes_IN  pInBfr = (PSM_GetAdapterPortAttributes_IN)Buffer;
                    PSM_GetAdapterPortAttributes_OUT pOutBfr = (PSM_GetAdapterPortAttributes_OUT)Buffer;
                    PMS_SMHBA_FC_Port pPortSpecificAttributes = NULL;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetAdapterPortAttributes\n");
                    #endif
                    size = FIELD_OFFSET(SM_GetAdapterPortAttributes_OUT, PortAttributes) + FIELD_OFFSET(MS_SMHBA_PORTATTRIBUTES, PortSpecificAttributes) + sizeof(MS_SMHBA_FC_Port);
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetAdapterPortAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                    pOutBfr->HBAStatus = HBA_STATUS_OK;
                    CopyUnicodeString(pOutBfr->PortAttributes.OSDeviceName, MODEL, sizeof(pOutBfr->PortAttributes.OSDeviceName));
                    pOutBfr->PortAttributes.PortState = HBA_PORTSTATE_ONLINE;
                    pOutBfr->PortAttributes.PortType = HBA_PORTTYPE_SASDEVICE;
                    pOutBfr->PortAttributes.PortSpecificAttributesSize = sizeof(MS_SMHBA_FC_Port);
                    pPortSpecificAttributes = (PMS_SMHBA_FC_Port) pOutBfr->PortAttributes.PortSpecificAttributes;
                    RtlZeroMemory(pPortSpecificAttributes, sizeof(MS_SMHBA_FC_Port));
                    RtlMoveMemory(pPortSpecificAttributes->NodeWWN, &adaptExt->wwn, sizeof(pPortSpecificAttributes->NodeWWN));
                    RtlMoveMemory(pPortSpecificAttributes->PortWWN, &adaptExt->port_wwn, sizeof(pPortSpecificAttributes->PortWWN));
                    pPortSpecificAttributes->FcId = 0;
                    pPortSpecificAttributes->PortSupportedClassofService = 0;
//FIXME report PortSupportedFc4Types PortActiveFc4Types FabricName;
                    pPortSpecificAttributes->NumberofDiscoveredPorts = 1;
                    pPortSpecificAttributes->NumberofPhys = 1;
                    CopyUnicodeString(pPortSpecificAttributes->PortSymbolicName, PORTSYMBOLICNAME, sizeof(pPortSpecificAttributes->PortSymbolicName));
                }
                break;
                case SM_GetDiscoveredPortAttributes:
                {
                    PSM_GetDiscoveredPortAttributes_IN  pInBfr = (PSM_GetDiscoveredPortAttributes_IN)Buffer;
                    PSM_GetDiscoveredPortAttributes_OUT pOutBfr = (PSM_GetDiscoveredPortAttributes_OUT)Buffer;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetDiscoveredPortAttributes\n");
                    #endif
                    size = SM_GetDiscoveredPortAttributes_OUT_SIZE;
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetDiscoveredPortAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                    pOutBfr->HBAStatus = HBA_STATUS_OK;
                    CopyUnicodeString(pOutBfr->PortAttributes.OSDeviceName, MODEL, sizeof(pOutBfr->PortAttributes.OSDeviceName));
                    pOutBfr->PortAttributes.PortState = HBA_PORTSTATE_ONLINE;
                    pOutBfr->PortAttributes.PortType = HBA_PORTTYPE_SASDEVICE;
                }
                break;
                case SM_GetPortAttributesByWWN:
                {
                    PSM_GetPortAttributesByWWN_IN  pInBfr = (PSM_GetPortAttributesByWWN_IN)Buffer;
                    PSM_GetPortAttributesByWWN_OUT pOutBfr = (PSM_GetPortAttributesByWWN_OUT)Buffer;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPortAttributesByWWN\n");
                    #endif
                    size = SM_GetPortAttributesByWWN_OUT_SIZE;
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetPortAttributesByWWN_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                    pOutBfr->HBAStatus = HBA_STATUS_OK;
                    CopyUnicodeString(pOutBfr->PortAttributes.OSDeviceName, MODEL, sizeof(pOutBfr->PortAttributes.OSDeviceName));
                    pOutBfr->PortAttributes.PortState = HBA_PORTSTATE_ONLINE;
                    pOutBfr->PortAttributes.PortType = HBA_PORTTYPE_SASDEVICE;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPortAttributesByWWN Not Implemented Yet\n");
                    #endif
                }
                break;
                case SM_GetProtocolStatistics:
                {
                    PSM_GetProtocolStatistics_IN  pInBfr = (PSM_GetProtocolStatistics_IN)Buffer;
                    PSM_GetProtocolStatistics_OUT pOutBfr = (PSM_GetProtocolStatistics_OUT)Buffer;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetProtocolStatistics\n");
                    #endif
                    size = SM_GetProtocolStatistics_OUT_SIZE;
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetProtocolStatistics_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                }
                break;
                case SM_GetPhyStatistics:
                {
                    PSM_GetPhyStatistics_IN  pInBfr = (PSM_GetPhyStatistics_IN)Buffer;
                    PSM_GetPhyStatistics_OUT pOutBfr = (PSM_GetPhyStatistics_OUT)Buffer;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPhyStatistics\n");
                    #endif
                    size = FIELD_OFFSET(SM_GetPhyStatistics_OUT, PhyCounter) + sizeof(LONGLONG);
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetPhyStatistics_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                }
                break;
                case SM_GetFCPhyAttributes:
                {
                    PSM_GetFCPhyAttributes_IN  pInBfr = (PSM_GetFCPhyAttributes_IN)Buffer;
                    PSM_GetFCPhyAttributes_OUT pOutBfr = (PSM_GetFCPhyAttributes_OUT)Buffer;

                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetFCPhyAttributes\n");
                    #endif
                    size = SM_GetFCPhyAttributes_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetFCPhyAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                }
                break;
                case SM_GetSASPhyAttributes:
                {
                    PSM_GetSASPhyAttributes_IN  pInBfr = (PSM_GetSASPhyAttributes_IN)Buffer;
                    PSM_GetSASPhyAttributes_OUT pOutBfr = (PSM_GetSASPhyAttributes_OUT)Buffer;
                    #if !defined(RUN_UNCHECKED)
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetSASPhyAttributes\n");
                    #endif
                    size = SM_GetSASPhyAttributes_OUT_SIZE;
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }
                    if (InBufferSize < SM_GetSASPhyAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_ERROR;
                        break;
                    }
                }
                break;
                case SM_RefreshInformation:
                {
                }
                break;
                default:
                    status = SRB_STATUS_INVALID_REQUEST;
                    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                    RhelDbgPrint(TRACE_LEVEL_ERROR, " --> ERROR Unknown MethodId = %lu\n", MethodId);
                    #endif
                    break;
            }
        }
        break;
        default:
            status = SRB_STATUS_INVALID_REQUEST;
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " --> VioScsiExecuteWmiMethod Unsupported GuidIndex = %lu\n", GuidIndex);
            #endif
        break;
    }
    ScsiPortWmiPostProcess(RequestContext,
        status,
        size);

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return SRB_STATUS_SUCCESS;

}

UCHAR
VioScsiQueryWmiRegInfo(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    OUT PWCHAR *MofResourceName
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(RequestContext);

    *MofResourceName = VioScsiWmi_MofResourceName;

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return SRB_STATUS_SUCCESS;
}

VOID
VioScsiReadExtendedData(
IN PVOID Context,
OUT PUCHAR Buffer
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    UCHAR numberOfBytes = sizeof(VioScsiExtendedInfo) - 1;
    PADAPTER_EXTENSION    adaptExt;
    PVioScsiExtendedInfo  extInfo;

    adaptExt = (PADAPTER_EXTENSION)Context;
    extInfo = (PVioScsiExtendedInfo)Buffer;

    RtlZeroMemory(Buffer, numberOfBytes);

    extInfo->QueueDepth = (ULONG)adaptExt->queue_depth;
    extInfo->QueuesCount = (UCHAR)adaptExt->num_queues;
    extInfo->Indirect = CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC);
    extInfo->EventIndex = CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX);
    extInfo->RingPacked = CHECKBIT(adaptExt->features, VIRTIO_F_RING_PACKED);
    extInfo->DpcRedirection = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_DPC_REDIRECTION);
    extInfo->ConcurrentChannels = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_CONCURRENT_CHANNELS);
    extInfo->InterruptMsgRanges = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_INTERRUPT_MESSAGE_RANGES);
    extInfo->CompletionDuringStartIo = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO);
    extInfo->PhysicalBreaks = adaptExt->max_physical_breaks;
    extInfo->ResponseTime = adaptExt->resp_time;

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}
